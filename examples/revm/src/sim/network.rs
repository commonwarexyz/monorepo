//! Simulated network setup for the tokio runtime simulation.
//!
//! The example uses `commonware_p2p::simulated` with a full mesh of links.

use super::{MAX_MSG_SIZE, P2P_LINK_LATENCY_MS};
use anyhow::Context as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{simulated, Manager as _};
use commonware_runtime::{tokio, Metrics as _};
use commonware_utils::ordered::Set;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

/// Boot the simulated p2p network and register the participant set.
pub(super) async fn start_network(
    context: &tokio::Context,
    participants: Set<ed25519::PublicKey>,
) -> simulated::Oracle<ed25519::PublicKey, tokio::Context> {
    let base_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (network, oracle) = simulated::Network::new_with_base_addr(
        context.with_label("network"),
        simulated::Config {
            max_size: MAX_MSG_SIZE as u32,
            disconnect_on_block: true,
            tracked_peer_sets: None,
        },
        base_addr,
    );
    network.start();

    oracle.manager().update(0, participants).await;
    oracle
}

/// Connect all peers in a full mesh with fixed links.
/// Connect every registered peer to every other peer (full mesh).
pub(super) async fn connect_all_peers(
    oracle: &mut simulated::Oracle<ed25519::PublicKey, tokio::Context>,
    peers: &[ed25519::PublicKey],
) -> anyhow::Result<()> {
    for a in peers.iter() {
        for b in peers.iter() {
            if a == b {
                continue;
            }
            oracle
                .add_link(
                    a.clone(),
                    b.clone(),
                    simulated::Link {
                        latency: Duration::from_millis(P2P_LINK_LATENCY_MS),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .context("add_link")?;
        }
    }
    Ok(())
}
