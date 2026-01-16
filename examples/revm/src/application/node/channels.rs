use super::config::{
    ChannelReceiver, ChannelSender, Peer, CHANNEL_BACKFILL, CHANNEL_BLOCKS, CHANNEL_CERTS,
    CHANNEL_RESOLVER, CHANNEL_VOTES,
};
use anyhow::Context as _;
use commonware_p2p::simulated;
use governor::Quota;

pub(super) struct NodeChannels {
    /// Channel pair used for voting traffic.
    pub(super) votes: (ChannelSender, ChannelReceiver),
    /// Channel pair used for certificate gossip.
    pub(super) certs: (ChannelSender, ChannelReceiver),
    /// Channel pair used for resolver/backfill control requests.
    pub(super) resolver: (ChannelSender, ChannelReceiver),
    /// Channel pair used for full block broadcast.
    pub(super) blocks: (ChannelSender, ChannelReceiver),
    /// Channel pair used for marshal backfill responses.
    pub(super) backfill: (ChannelSender, ChannelReceiver),
}

/// Register the simulated transport channels for a node.
pub(super) async fn register_channels(
    control: &mut simulated::Control<Peer, commonware_runtime::tokio::Context>,
    quota: Quota,
) -> anyhow::Result<NodeChannels> {
    let votes = control
        .register(CHANNEL_VOTES, quota)
        .await
        .context("register votes channel")?;
    let certs = control
        .register(CHANNEL_CERTS, quota)
        .await
        .context("register certs channel")?;
    let resolver = control
        .register(CHANNEL_RESOLVER, quota)
        .await
        .context("register resolver channel")?;
    let blocks = control
        .register(CHANNEL_BLOCKS, quota)
        .await
        .context("register blocks channel")?;
    let backfill = control
        .register(CHANNEL_BACKFILL, quota)
        .await
        .context("register backfill channel")?;

    Ok(NodeChannels {
        votes,
        certs,
        resolver,
        blocks,
        backfill,
    })
}
