//! Simulated network setup for the tokio runtime simulation.
//!
//! The example uses `commonware_p2p::simulated` with a full mesh of links.

use super::{MAX_MSG_SIZE, P2P_LINK_LATENCY_MS};
use anyhow::Context as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{simulated, Manager as _};
use commonware_runtime::{tokio, Metrics as _};
use commonware_utils::ordered::Set;
use std::time::Duration;

pub(super) async fn start_network(
    context: &tokio::Context,
    participants: Set<ed25519::PublicKey>,
) -> simulated::Oracle<ed25519::PublicKey> {
    let (network, oracle) = simulated::Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: MAX_MSG_SIZE,
            disconnect_on_block: true,
            tracked_peer_sets: None,
        },
    );
    network.start();

    oracle.manager().update(0, participants).await;
    oracle
}

/// Connect all peers in a full mesh with fixed links.
pub(super) async fn connect_all_peers(
    oracle: &mut simulated::Oracle<ed25519::PublicKey>,
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
