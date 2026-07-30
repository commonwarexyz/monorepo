//! Authenticated lookup helpers backed by the deterministic runtime network.

use commonware_cryptography::Signer;
use commonware_runtime::{
    Supervisor as _,
    deterministic::{self, network as deterministic_network},
};
use std::net::SocketAddr;

/// Authenticated lookup network backed by the deterministic runtime transport.
pub type LookupNetwork<C> = crate::authenticated::lookup::AcceptingNetwork<
    deterministic::Context,
    C,
    deterministic_network::Network<deterministic::Context>,
    deterministic_network::Network<deterministic::Context>,
    crate::authenticated::lookup::UnrestrictedAdmission,
>;

impl crate::PeerEndpoint for deterministic_network::Endpoint {}

/// Constructs a real authenticated lookup network over a deterministic transport node.
///
/// The returned network has no application channels or tracked peers yet. Configure those through
/// the normal lookup APIs. Topology and fault controls remain on `transport`.
pub fn lookup<C: Signer>(
    context: deterministic::Context,
    transport: &deterministic_network::Oracle<deterministic::Context>,
    crypto: C,
    endpoint: deterministic_network::Endpoint,
    namespace: &[u8],
    max_message_size: u32,
) -> (
    LookupNetwork<C>,
    crate::authenticated::lookup::ReachabilityOracle<C::PublicKey, deterministic_network::Endpoint>,
) {
    let config = crate::authenticated::lookup::GenericConfig::from(
        crate::authenticated::lookup::Config::local(
            crypto,
            namespace,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            max_message_size,
        ),
    );
    let max_concurrent_handshakes = commonware_utils::NZU32!(1_024);
    let node = transport.register(context.child("transport"), endpoint, None);
    let (dialer, acceptor) = node.split();
    let (network, oracle) =
        crate::authenticated::lookup::DialOnlyNetwork::new(context.child("lookup"), dialer, config);
    (
        network.accepting(
            acceptor,
            endpoint,
            crate::authenticated::lookup::UnrestrictedAdmission,
            max_concurrent_handshakes,
        ),
        oracle,
    )
}

#[cfg(test)]
pub(crate) mod lookup_test {
    use super::*;
    use crate::{
        Advertisement, CheckedSender as _, LimitedSender as _, Reachability,
        ReachabilityManager as _, ReachableTrackedPeers, Recipients,
        authenticated::lookup::{ReachabilityOracle, Receiver, Sender},
    };
    use commonware_cryptography::ed25519;
    use commonware_runtime::{Clock as _, Quota};
    use commonware_utils::{
        NZU32,
        ordered::{Map, Set},
    };
    use std::time::Duration;

    const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
    const MESSAGE_BACKLOG: usize = 128;
    const NAMESPACE: &[u8] = b"_COMMONWARE_P2P_UTILS_LOOKUP_TEST";
    const CHANNEL: crate::Channel = 0;

    pub(crate) type LookupSender = Sender<ed25519::PublicKey, deterministic::Context>;
    pub(crate) type LookupReceiver = Receiver<ed25519::PublicKey>;
    pub(crate) type LookupOracle =
        ReachabilityOracle<ed25519::PublicKey, deterministic_network::Endpoint>;

    pub(crate) struct Peer {
        pub(crate) key: ed25519::PublicKey,
        pub(crate) oracle: LookupOracle,
        channel: Option<(LookupSender, LookupReceiver)>,
    }

    impl Peer {
        pub(crate) const fn take_channel(&mut self) -> (LookupSender, LookupReceiver) {
            self.channel.take().expect("lookup channel already taken")
        }
    }

    /// Starts authenticated lookup peers over a fully connected deterministic transport.
    pub(crate) async fn start_peers(context: &deterministic::Context, count: usize) -> Vec<Peer> {
        let transport = deterministic_network::Oracle::new(Default::default());
        let link = deterministic_network::Link::new(Duration::ZERO);

        for from in 0..count {
            for to in 0..count {
                if from == to {
                    continue;
                }
                transport
                    .set_link(endpoint(from), endpoint(to), link)
                    .expect("peer endpoint should exist");
            }
        }

        let keys: Vec<_> = (0..count)
            .map(|seed| ed25519::PrivateKey::from_seed(seed as u64))
            .collect();
        let public_keys: Vec<_> = keys.iter().map(|key| key.public_key()).collect();
        let mut peers = Vec::with_capacity(count);

        for (index, key) in keys.into_iter().enumerate() {
            let (mut network, mut oracle) = lookup(
                context.child("peer"),
                &transport,
                key,
                endpoint(index),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
            );
            let tracked = public_keys
                .iter()
                .enumerate()
                .filter(|(peer_index, _)| *peer_index != index)
                .map(|(peer_index, peer)| {
                    let advertisement = Advertisement::new(vec![endpoint(peer_index)])
                        .expect("one endpoint is a valid advertisement");
                    (peer.clone(), Reachability::Dialable(advertisement))
                });
            oracle.track(
                0,
                ReachableTrackedPeers::primary(Map::from_iter_dedup(tracked)),
            );
            let channel = network.register(
                CHANNEL,
                Quota::per_second(NZU32!(1_000_000)),
                MESSAGE_BACKLOG,
            );
            network.start();
            peers.push(Peer {
                key: public_keys[index].clone(),
                oracle,
                channel: Some(channel),
            });
        }

        for (index, peer) in peers.iter_mut().enumerate() {
            let expected = Set::from_iter_dedup(
                public_keys
                    .iter()
                    .enumerate()
                    .filter(|(peer_index, _)| *peer_index != index)
                    .map(|(_, peer)| peer.clone()),
            );
            wait_for_connected(context, &mut peer.channel.as_mut().unwrap().0, &expected).await;
        }

        peers
    }

    pub(crate) async fn wait_for_connected(
        context: &deterministic::Context,
        sender: &mut LookupSender,
        expected: &Set<ed25519::PublicKey>,
    ) {
        let deadline = context.current() + Duration::from_secs(30);
        loop {
            let connected = sender
                .check(Recipients::All)
                .map(|checked| Set::from_iter_dedup(checked.recipients()))
                .unwrap_or_default();
            if &connected == expected {
                return;
            }
            assert!(
                context.current() < deadline,
                "lookup peers did not become ready: expected {expected:?}, got {connected:?}"
            );
            context.sleep(Duration::from_millis(1)).await;
        }
    }

    const fn endpoint(index: usize) -> deterministic_network::Endpoint {
        deterministic_network::Endpoint::new(index as u64)
    }
}
