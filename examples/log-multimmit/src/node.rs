//! One node: telemetry or terminal UI, network, marshal, application, and consensus.

use crate::{
    LOG_TARGET,
    application::{self, Body},
    committee,
    config::{Output, RunConfig},
    gui::Gui,
    marshal::{self, Transport},
    progress, trace_file,
};
use commonware_consensus::{
    Reporters,
    multimmit::{self, Engine, Planes, marshal::Limits},
    types::Participant,
};
use commonware_cryptography::{ChaCha20Poly1305, Hasher as _, Sha256, Signer as _};
use commonware_p2p::{
    Manager as _,
    authenticated::{self, discovery},
    utils::lossy::LossyReceiver,
};
use commonware_parallel::{Rayon, rayon::ThreadPoolBuilder};
use commonware_runtime::{
    Quota, Supervisor as _,
    buffer::paged::{self, CacheRef},
    telemetry::metrics::MetricsExt as _,
    tokio,
};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{NZU32, NZUsize, TestRng, ordered::Set};
use std::{
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};
use tracing::info;

/// Network namespace for this example's authenticated traffic.
const P2P_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_P2P";

/// Namespace that separates the random streams of injected message loss.
const LOSS_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_LOSS";

/// Channel carrying data-availability shares and certificates.
const DATA_CHANNEL: u64 = 0;
/// Channel carrying consensus artifacts.
const CONSENSUS_CHANNEL: u64 = 1;
/// Channel carrying certificates.
const CERTIFICATE_CHANNEL: u64 = 2;
/// Channel carrying consensus artifact recovery.
const ENGINE_RESOLVER_CHANNEL: u64 = 3;
/// Channel carrying exact block backfill.
const MARSHAL_RESOLVER_CHANNEL: u64 = 4;
/// Channel carrying complete block bodies.
const MARSHAL_BROADCAST_CHANNEL: u64 = 5;

/// Messages each peer may send per second on each channel.
///
/// Views are not paced by a timer: a view exits as soon as its V-QC forms, so the consensus
/// channel carries n-f votes per view at whatever rate the network sustains. A quota sized for
/// one view per second (as in `examples/log`, which runs Simplex) would throttle view exits
/// while the producer chains, paced by their own certificates, kept running.
const CHANNEL_RATE: NonZeroU32 = NZU32!(1_024);

/// Storage partition prefix shared by the consensus engine and marshal.
pub(crate) const PARTITION_PREFIX: &str = "log_multimmit";

/// Logical page size of the engine's page cache.
const ENGINE_PAGE_SIZE: NonZeroU16 = paged::page_size(16_384);

/// Pages held by the engine's page cache.
const ENGINE_CACHE_PAGES: NonZeroUsize = NZUsize!(2);

/// Messages buffered by the engine and application mailboxes.
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1_024);

/// Most recent local blocks tracked from input submission to finality and ordering.
///
/// A producer has at most a pipeline of blocks in flight, so this covers every block a benchmark
/// window can still observe.
const TRACKED_BLOCKS: NonZeroUsize = NZUsize!(1_024);

/// Framing headroom above the largest resolver response in one network message.
const MESSAGE_ENVELOPE_BYTES: usize = 1_024;

/// Smallest network message bound, whatever the body size.
const MIN_MESSAGE_BYTES: usize = 1024 * 1024;

/// Returns the network message bound for blocks of `max_block_size`.
fn max_message_size(max_block_size: usize) -> u32 {
    u32::try_from(
        Limits::for_block_bytes(
            NonZeroUsize::new(max_block_size).expect("encoded blocks are non-empty"),
        )
        .max_response_bytes
        .get()
        .checked_add(MESSAGE_ENVELOPE_BYTES)
        .expect("resolver response and transport envelope must fit in memory")
        .max(MIN_MESSAGE_BYTES),
    )
    .expect("resolver response and transport envelope must fit in the network codec")
}

/// Returns the seed of the loss stream of `channel` at node `key` in the committee of `seed`, so
/// every node and channel samples drops independently and a repetition can be replayed.
fn loss_seed(seed: u64, key: u64, channel: u64) -> u64 {
    let digest = Sha256::hash(&[
        LOSS_NAMESPACE,
        &seed.to_be_bytes(),
        &key.to_be_bytes(),
        &channel.to_be_bytes(),
    ]);
    u64::from_be_bytes(digest.as_ref()[..8].try_into().expect("digest has 8 bytes"))
}

/// How the node reports progress once consensus is running.
enum Mode {
    Headless,
    Terminal(Box<Gui<tokio::Context>>),
}

/// Runs one node until consensus stops or the user quits the terminal UI.
pub async fn run(context: tokio::Context, config: RunConfig) {
    let index = config.index();
    let key = config.identity.key;
    let port = config.identity.port;
    let committee = committee::derive(&config);
    let loss = config.loss();
    let proposal_policy = config.proposal_policy();
    let committee_seed = config
        .benchmark
        .as_ref()
        .map_or(0, |benchmark| benchmark.committee_seed);
    let producer_chain = committee
        .config
        .producer_chain(Participant::from_usize(index));

    // Headless nodes log through the runtime's telemetry; the terminal UI owns stdout, so its
    // tracing goes to an optional file that must outlive every service.
    let mut trace_guard = None;
    let mode = match config.output {
        Output::Headless(telemetry) => {
            let traces = telemetry.traces.map(|traces| tokio::tracing::Config {
                endpoint: traces.endpoint,
                name: key.to_string(),
                rate: traces.rate,
            });
            tokio::telemetry::init(
                context.child("telemetry"),
                tokio::telemetry::Logs {
                    level: telemetry.log_level,
                    json: true,
                },
                telemetry.metrics,
                traces,
            );
            Mode::Headless
        }
        Output::Terminal { trace_file: path } => {
            trace_guard = path.map(|path| trace_file::install(&path).expect("trace file opens"));
            Mode::Terminal(Box::new(Gui::new(
                context.child("gui"),
                u32::try_from(index).expect("participant index is representable"),
                producer_chain.map(|chain| chain.get()),
            )))
        }
    };
    let identity = committee.identities[index].clone();
    info!(target: LOG_TARGET, key = ?identity, port, "loaded signer");
    info!(
        target: LOG_TARGET,
        loss = loss.as_f64(),
        ?proposal_policy,
        "injected faults"
    );

    // Start the network with one channel per protocol plane.
    let validators = Set::try_from(committee.identities.clone()).expect("participants are unique");
    let bootstrappers = config
        .network
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            let position = config
                .network
                .participants
                .iter()
                .position(|participant| *participant == bootstrapper.key)
                .expect("validated bootstrapper is a participant");
            (
                committee.identities[position].clone(),
                bootstrapper.address.into(),
            )
        })
        .collect();
    let network_key = committee.network_keys[index].clone();
    let max_peers_per_set =
        authenticated::peer_set_limit(validators.iter(), &network_key.public_key());
    let max_block_size = Body::max_block_size(config.tuning.body_size);
    let p2p = discovery::Config::local(
        Cups::<_, ChaCha20Poly1305>::new(
            Sake {
                signer: network_key,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(10),
                version: sake::Version::V1,
            },
            cups::Version::V1,
        ),
        P2P_NAMESPACE,
        SocketAddr::new(config.network.listen_ip, port),
        SocketAddr::new(config.network.public_ip, port),
        bootstrappers,
        max_peers_per_set,
        max_message_size(max_block_size),
        MAILBOX_SIZE,
    );
    let (mut network, mut oracle) = discovery::Network::new(context.child("network"), p2p);
    oracle.track(0, validators);
    let quota = Quota::per_second(CHANNEL_RATE);
    // Every channel drops received messages with the benchmark's loss rate, which is zero
    // without one, so the protocol sees a uniform receiver type either way.
    let dropped = context.counter(
        "network_injected_loss_dropped",
        "received messages dropped by injected loss",
    );
    let mut register = |channel| {
        let (sender, receiver) = network.register(channel, quota);
        let rng = TestRng::new(loss_seed(committee_seed, key, channel));
        (
            sender,
            LossyReceiver::new(receiver, loss, rng, dropped.clone()),
        )
    };
    let data = register(DATA_CHANNEL);
    let consensus = register(CONSENSUS_CHANNEL);
    let certificates = register(CERTIFICATE_CHANNEL);
    let engine_resolver = register(ENGINE_RESOLVER_CHANNEL);
    let marshal_resolver = register(MARSHAL_RESOLVER_CHANNEL);
    let marshal_broadcast = register(MARSHAL_BROADCAST_CHANNEL);
    let network_handle = network.start();

    // Start marshal, which disseminates, stores, and orders complete blocks.
    let strategy = Rayon::new(ThreadPoolBuilder::new(config.tuning.compute_threads))
        .expect("verification pool starts");
    let participants = committee.codec().participants();
    let benchmark_quorum = config
        .benchmark
        .as_ref()
        .map(|_| NonZeroUsize::new(committee.codec().view_quorum()).expect("nonzero quorum"));
    let (application, application_mailbox) = application::Actor::new(
        context.child("application"),
        application::Config {
            seed: key,
            production: application::Production {
                body_size: config.tuning.body_size,
                interval: config.tuning.production_interval(),
                offered_bytes_per_second: config.tuning.offered_bytes_per_second,
                schedule: config.benchmark.map(|benchmark| benchmark.schedule),
            },
            tracked_blocks: TRACKED_BLOCKS,
            producer_chain,
            benchmark_quorum,
            mailbox_size: MAILBOX_SIZE,
        },
    );
    let sink = match &mode {
        Mode::Headless => None,
        Mode::Terminal(gui) => Some(gui.reporter()),
    };
    let (marshal, relay, marshal_services) = marshal::start(
        &context,
        &committee,
        identity,
        &strategy,
        &config.tuning,
        Transport {
            oracle: oracle.clone(),
            broadcast: marshal_broadcast,
            resolver: marshal_resolver,
        },
        application::OutputReporter::new(application_mailbox.clone(), sink),
    )
    .await;

    // The application builds bodies and marshal keeps them; consensus receives only their
    // canonical header digests, and marshal's relay broadcasts the bodies.
    let application_handle = application.start(marshal.clone());

    // View-critical cryptography gets its own pool: signing, certificate assembly, and the
    // verdicts the round waits on never queue behind the data plane's bulk verification.
    let critical_threads = config
        .tuning
        .critical_threads
        .unwrap_or_else(|| multimmit::critical_threads(participants));
    let critical_strategy =
        Rayon::new(ThreadPoolBuilder::new(critical_threads)).expect("critical pool starts");
    let engine = Engine::open(
        context.child("engine"),
        multimmit::Config::<Sha256, _, _, _, _, _, _, _> {
            scheme: committee.signers[index].clone(),
            genesis: committee.config.genesis().clone(),
            tuning: multimmit::config::Tuning {
                proposal_policy,
                ..committee::tuning()
            },
            automaton: application_mailbox.clone(),
            relay,
            // Marshal receives every activity; the application keeps only what it tracks.
            reporter: Reporters::from((marshal, application_mailbox)),
            strategy,
            critical_strategy,
            blocker: oracle,
            partition_prefix: String::from(PARTITION_PREFIX),
            page_cache: CacheRef::new(ENGINE_PAGE_SIZE, ENGINE_CACHE_PAGES),
            mailbox_size: MAILBOX_SIZE,
        },
    )
    .await
    .expect("engine opens");
    let mut running = engine.start(Planes {
        data,
        consensus,
        certificates,
        resolver: engine_resolver,
    });
    running.ready().await.expect("engine becomes ready");
    let inspector = running.inspector().clone();

    match mode {
        Mode::Headless => progress::log(&context, inspector).await,
        Mode::Terminal(gui) => gui.run(inspector).await,
    }

    // Stop consumers before the services they depend on. The engine was aborted, so its join
    // reports the abort.
    running.abort();
    let _ = running.join().await;
    application_handle.abort();
    let _ = application_handle.await;
    marshal_services.stop().await;
    network_handle.abort();
    let _ = network_handle.await;
    drop(trace_guard);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_streams_differ_across_repetitions_nodes_and_channels() {
        let seeds = [
            loss_seed(1, 0, DATA_CHANNEL),
            loss_seed(2, 0, DATA_CHANNEL),
            loss_seed(1, 1, DATA_CHANNEL),
            loss_seed(1, 0, CONSENSUS_CHANNEL),
        ];
        for (index, seed) in seeds.iter().enumerate() {
            assert!(!seeds[..index].contains(seed));
        }
        assert_eq!(seeds[0], loss_seed(1, 0, DATA_CHANNEL));
    }

    #[test]
    fn network_messages_fit_backfill_responses() {
        assert_eq!(max_message_size(Body::max_block_size(1_024)), 1_048_576);
        assert_eq!(
            max_message_size(Body::max_block_size(1024 * 1024)),
            16_779_888
        );
    }
}
