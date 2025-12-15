//! Node wiring for the deterministic simulation.
//!
//! Each node runs:
//! - a chain application actor (block production/verification and out-of-band block gossip), and
//! - a threshold-simplex engine instance that orders opaque digests.

use super::{
    demo, simplex, ThresholdScheme, BLOCK_CODEC_MAX_CALLDATA, BLOCK_CODEC_MAX_TXS, CHANNEL_BLOCKS,
    CHANNEL_CERTS, CHANNEL_RESOLVER, CHANNEL_VOTES, MAILBOX_SIZE,
};
use crate::{application, consensus};
use anyhow::Context as _;
use commonware_consensus::types::{Epoch, ViewDelta};
use commonware_cryptography::ed25519;
use commonware_p2p::{simulated, Receiver as _};
use commonware_runtime::{buffer::PoolRef, deterministic, Metrics as _, Spawner as _};
use commonware_utils::{NZUsize, NZU32};
use futures::channel::mpsc;
use governor::Quota;
use std::time::Duration;

type Peer = ed25519::PublicKey;
type ChannelSender = simulated::Sender<Peer>;
type ChannelReceiver = simulated::Receiver<Peer>;

type ConsensusConfig = simplex::Config<
    Peer,
    ThresholdScheme,
    simulated::Control<Peer>,
    consensus::ConsensusDigest,
    consensus::Mailbox,
    consensus::Mailbox,
    consensus::Mailbox,
>;

struct NodeChannels {
    votes: (ChannelSender, ChannelReceiver),
    certs: (ChannelSender, ChannelReceiver),
    resolver: (ChannelSender, ChannelReceiver),
    blocks: (ChannelSender, ChannelReceiver),
}

struct NodeInit<'a> {
    index: usize,
    public_key: Peer,
    scheme: ThresholdScheme,
    quota: Quota,
    buffer_pool: PoolRef,
    finalized_tx: mpsc::UnboundedSender<consensus::FinalizationEvent>,
    demo: &'a demo::DemoTransfer,
}

struct SimplexStart {
    index: usize,
    scheme: ThresholdScheme,
    blocker: simulated::Control<Peer>,
    mailbox: consensus::Mailbox,
    buffer_pool: PoolRef,
    votes: (ChannelSender, ChannelReceiver),
    certs: (ChannelSender, ChannelReceiver),
    resolver: (ChannelSender, ChannelReceiver),
}

/// Spawn all nodes (application + consensus) for a simulation run.
pub(super) async fn start_all_nodes(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<ed25519::PublicKey>,
    participants: &[ed25519::PublicKey],
    schemes: &[ThresholdScheme],
    demo: &demo::DemoTransfer,
) -> anyhow::Result<(
    Vec<application::Handle>,
    mpsc::UnboundedReceiver<consensus::FinalizationEvent>,
)> {
    // Per-channel rate limit used by the simulated P2P transport in this example.
    let quota = Quota::per_second(NZU32!(1_000));
    let buffer_pool = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

    let (finalized_tx, finalized_rx) = mpsc::unbounded::<consensus::FinalizationEvent>();
    let mut nodes = Vec::with_capacity(participants.len());

    for (i, pk) in participants.iter().cloned().enumerate() {
        let handle = start_node(
            context,
            oracle,
            NodeInit {
                index: i,
                public_key: pk,
                scheme: schemes[i].clone(),
                quota,
                buffer_pool: buffer_pool.clone(),
                finalized_tx: finalized_tx.clone(),
                demo,
            },
        )
        .await?;
        nodes.push(handle);
    }

    Ok((nodes, finalized_rx))
}

async fn start_node(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<Peer>,
    init: NodeInit<'_>,
) -> anyhow::Result<application::Handle> {
    let NodeInit {
        index,
        public_key,
        scheme,
        quota,
        buffer_pool,
        finalized_tx,
        demo,
    } = init;

    let mut control = oracle.control(public_key.clone());
    let blocker = control.clone();

    let NodeChannels {
        votes,
        certs,
        resolver,
        blocks: (block_sender, block_receiver),
    } = register_channels(&mut control, quota).await?;

    let (application, consensus_mailbox, handle) =
        start_application(index as u32, block_sender, finalized_tx, demo);

    spawn_block_forwarder(context, index, handle.clone(), block_receiver);

    spawn_application(context, index, application);

    // Submit the deterministic demo transfer before starting consensus so the first leader can
    // include it without relying on a hardcoded "height == 1" rule.
    let _ = handle.submit_tx(demo.tx.clone()).await;

    start_simplex_engine(
        context,
        SimplexStart {
            index,
            scheme,
            blocker,
            mailbox: consensus_mailbox,
            buffer_pool,
            votes,
            certs,
            resolver,
        },
    );

    Ok(handle)
}

async fn register_channels(
    control: &mut simulated::Control<Peer>,
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

    Ok(NodeChannels {
        votes,
        certs,
        resolver,
        blocks,
    })
}

fn start_application(
    node: u32,
    gossip: ChannelSender,
    finalized: mpsc::UnboundedSender<consensus::FinalizationEvent>,
    demo: &demo::DemoTransfer,
) -> (
    application::Application<ChannelSender>,
    consensus::Mailbox,
    application::Handle,
) {
    application::Application::new(
        node,
        application::BlockCodecCfg {
            max_txs: BLOCK_CODEC_MAX_TXS,
            max_calldata_bytes: BLOCK_CODEC_MAX_CALLDATA,
        },
        MAILBOX_SIZE,
        gossip,
        finalized,
        demo.alloc.clone(),
    )
}

fn spawn_block_forwarder(
    context: &deterministic::Context,
    index: usize,
    handle: application::Handle,
    mut receiver: ChannelReceiver,
) {
    context
        .with_label(&format!("block_receiver_{index}"))
        .spawn(move |_ctx| async move {
            while let Ok((from, bytes)) = receiver.recv().await {
                handle.deliver_block(from, bytes).await;
            }
        });
}

fn spawn_application(
    context: &deterministic::Context,
    index: usize,
    application: application::Application<ChannelSender>,
) {
    context
        .with_label(&format!("application_{index}"))
        .spawn(move |_ctx| async move {
            application.run().await;
        });
}

fn start_simplex_engine(context: &deterministic::Context, start: SimplexStart) {
    let SimplexStart {
        index,
        scheme,
        blocker,
        mailbox,
        buffer_pool,
        votes,
        certs,
        resolver,
    } = start;
    let engine = simplex::Engine::new(
        context.with_label(&format!("engine_{index}")),
        simplex_config(index, scheme, blocker, mailbox, buffer_pool),
    );
    engine.start(votes, certs, resolver);
}

fn simplex_config(
    index: usize,
    scheme: ThresholdScheme,
    blocker: simulated::Control<Peer>,
    mailbox: consensus::Mailbox,
    buffer_pool: PoolRef,
) -> ConsensusConfig {
    simplex::Config {
        scheme,
        blocker,
        automaton: mailbox.clone(),
        relay: mailbox.clone(),
        reporter: mailbox,
        // NOTE: This is a *local* storage partition for the consensus journal. In the deterministic
        // simulation all nodes share the same runtime/storage instance, so each node must use a
        // unique partition to avoid sharing persisted state.
        partition: format!("revm-chain-{index}"),
        mailbox_size: MAILBOX_SIZE,
        epoch: Epoch::zero(),
        namespace: b"revm-chain-consensus".to_vec(),
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        leader_timeout: Duration::from_millis(50),
        notarization_timeout: Duration::from_millis(100),
        nullify_retry: Duration::from_millis(200),
        fetch_timeout: Duration::from_millis(200),
        activity_timeout: ViewDelta::new(10),
        skip_timeout: ViewDelta::new(5),
        fetch_concurrent: 16,
        fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
        buffer_pool,
    }
}
