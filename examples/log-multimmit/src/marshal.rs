//! Marshal wiring: storage sizing, L-QC verification, body broadcast, and body backfill.

use crate::{
    application::{Block, Body, Marshal, Relay},
    committee::Committee,
    config::NodeTuning,
    node::PARTITION_PREFIX,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Reporter,
    multimmit::marshal::{
        ArchiveConfig, ArchiveMode, Config, SchemeVerifier, ServiceHandle, Start, Update,
        open as open_marshal,
    },
    types::Participant,
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, ed25519};
use commonware_p2p::{Receiver, Sender, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_resolver::p2p as resolver;
use commonware_runtime::{
    BufferPooler, Handle, Supervisor as _,
    buffer::paged::{self, CacheRef},
    tokio,
};
use commonware_storage::translator::EightCap;
use commonware_utils::NZUsize;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

/// Application acknowledgements retained while a durable cursor publication is pending.
const DELIVERY_ACK_WINDOW: NonZeroUsize = NZUsize!(2_048);

/// Logical page size of marshal's archive page cache.
const ARCHIVE_PAGE_SIZE: NonZeroU16 = paged::page_size(16_384);

/// Pages held by marshal's archive page cache.
const ARCHIVE_CACHE_PAGES: NonZeroUsize = NZUsize!(256);

/// Messages buffered by the body broadcast and body backfill mailboxes.
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1_024);

/// Recent bodies buffered broadcast keeps per sender.
const BROADCAST_CACHE_BODIES: usize = 1_024;

/// How long a body backfill request waits for a response.
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);

/// How long body backfill waits before retrying a failed fetch.
const RESOLVER_RETRY: Duration = Duration::from_millis(100);

/// Builds marshal's configuration for this committee and body size.
///
/// Every size bound follows from the largest encoded block, so the configuration scales with
/// `--body-size` without separate knobs.
fn config(
    pooler: &impl BufferPooler,
    committee: &Committee,
    tuning: &NodeTuning,
) -> Config<EightCap, MinPk, Body> {
    let archive = ArchiveConfig::new(
        EightCap,
        CacheRef::from_pooler(pooler, ARCHIVE_PAGE_SIZE, ARCHIVE_CACHE_PAGES),
    );
    let mut config = Config::new(
        Start::Genesis(committee.config.genesis().clone()),
        PARTITION_PREFIX.into(),
        committee.codec(),
        Body::codec_config(tuning.body_size),
        archive,
    )
    .with_max_block_bytes(
        NonZeroUsize::new(Body::max_block_size(tuning.body_size))
            .expect("encoded blocks are non-empty"),
    );
    config.limits.max_hot_block_bytes = tuning.marshal_live_cache_bytes;
    config.limits.max_materialized_block_bytes = tuning.marshal_materialized_cache_bytes;
    config.capacities.max_pending_acks = DELIVERY_ACK_WINDOW;
    if let Some(bytes) = tuning.marshal_delivery_bytes {
        config.limits.max_delivery_bytes = bytes;
    }
    config.retention.lqc = ArchiveMode::Prunable;
    config.retention.history = ArchiveMode::Prunable;
    config.retention.blocks = ArchiveMode::Prunable;
    config
}

/// Handles of marshal and the transport services it runs on.
pub struct Services {
    marshal: ServiceHandle,
    resolver: Handle<()>,
    broadcast: Handle<()>,
}

impl Services {
    /// Stops marshal, then its transport services.
    pub async fn stop(mut self) {
        self.marshal.abort();
        self.marshal
            .join()
            .await
            .expect("marshal shuts down cleanly");
        for handle in [self.resolver, self.broadcast] {
            handle.abort();
            let _ = handle.await;
        }
    }
}

/// Peer tracking and channels for marshal's transport services.
pub struct Transport<S, R> {
    /// Peer set and blocker shared with the network.
    pub oracle: discovery::Oracle<ed25519::PublicKey>,
    /// Complete-block broadcast.
    pub broadcast: (S, R),
    /// Exact block backfill.
    pub resolver: (S, R),
}

/// Opens marshal storage and starts marshal with body broadcast and body backfill.
///
/// `reporter` receives the total order. Inbound bodies are decoded on `strategy` because body
/// decode checks the full-body digest. The returned relay can broadcast every recent block this
/// node staged that the engine may still ask it to publish.
pub async fn start<S, R>(
    context: &tokio::Context,
    committee: &Committee,
    identity: ed25519::PublicKey,
    strategy: &Rayon,
    tuning: &NodeTuning,
    transport: Transport<S, R>,
    reporter: impl Reporter<Activity = Update<Block>>,
) -> (Marshal, Relay, Services)
where
    S: Sender<PublicKey = ed25519::PublicKey>,
    R: Receiver<PublicKey = ed25519::PublicKey>,
{
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("body_broadcast"),
        buffered::Config {
            public_key: identity.clone(),
            mailbox_size: MAILBOX_SIZE,
            ingress_size: MAILBOX_SIZE,
            deque_size: BROADCAST_CACHE_BODIES,
            priority: false,
            codec_config: Body::codec_config(tuning.body_size),
            peer_provider: transport.oracle.clone(),
            blocker: transport.oracle.clone(),
            strategy: strategy.clone(),
        },
    );
    let broadcast = broadcast_engine.start(transport.broadcast);
    let (mut service, resolver_bridge) = open_marshal(
        context.child("marshal"),
        config(context, committee, tuning),
        buffer.clone(),
    )
    .await
    .expect("marshal storage opens");
    let (resolver_engine, resolver_mailbox) = resolver::Engine::new(
        context.child("body_resolver"),
        resolver::Config {
            peer_provider: transport.oracle.clone(),
            blocker: transport.oracle,
            consumer: resolver_bridge.clone(),
            producer: resolver_bridge,
            mailbox_size: MAILBOX_SIZE,
            me: Some(identity.clone()),
            timeout: RESOLVER_TIMEOUT,
            fetch_retry_timeout: RESOLVER_RETRY,
            // Body backfill bypasses ordinary outbound traffic.
            priority_requests: true,
            priority_responses: true,
        },
    );
    let resolver = resolver_engine.start(transport.resolver);
    let chain = committee
        .identities
        .iter()
        .position(|participant| *participant == identity)
        .and_then(|index| {
            committee
                .config
                .producer_chain(Participant::from_usize(index))
        });
    let relay = service.relay(chain);
    let verifier = SchemeVerifier::new(
        context.child("marshal_verifier"),
        committee.verifier.clone(),
        strategy.clone(),
    );
    let (mailbox, marshal) = service.start(resolver_mailbox, verifier, reporter);
    (
        mailbox,
        relay,
        Services {
            marshal,
            resolver,
            broadcast,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::multimmit::marshal::Limits;

    #[test]
    fn resolver_responses_page_large_blocks() {
        let max_block_size = Body::max_block_size(512 * 1024);
        assert_eq!(max_block_size, 524_387);
        assert_eq!(
            Limits::sized_resolver_max_value_bytes(NonZeroUsize::new(max_block_size).unwrap())
                .get(),
            8_390_193
        );
    }
}
