//! Validator node service entrypoint.

use crate::{
    application::{Coordinator, EpochSchemeProvider, SchemeProvider},
    engine,
    setup::{ParticipantConfig, PeerConfig},
};
use commonware_consensus::{
    marshal::resolver::p2p as p2p_resolver, simplex::signing_scheme::Scheme,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, Sha256, Signer};
use commonware_p2p::{authenticated::discovery, utils::requester};
use commonware_runtime::{tokio, Metrics};
use commonware_utils::{union, union_unique};
use futures::future::try_join_all;
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};
use tracing::{error, info};

const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_RESHARE";

const PENDING_CHANNEL: u64 = 0;
const RECOVERED_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BROADCASTER_CHANNEL: u64 = 3;
const BACKFILL_BY_DIGEST_CHANNEL: u64 = 4;
const DKG_CHANNEL: u64 = 5;

const MAILBOX_SIZE: usize = 10;
const MESSAGE_BACKLOG: usize = 10;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Run the validator node service.
pub async fn run<S: Scheme>(context: tokio::Context, args: super::ParticipantArgs)
where
    SchemeProvider<S, ed25519::PrivateKey>:
        EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
{
    // Load the participant configuration.
    let config_str = std::fs::read_to_string(&args.config_path)
        .expect("Failed to read participant configuration file");
    let config: ParticipantConfig =
        serde_json::from_str(&config_str).expect("Failed to deserialize participant configuration");

    // Load the peer configuration.
    let peers_str =
        std::fs::read_to_string(&args.peers_path).expect("Failed to read peers configuration file");
    let peer_config: PeerConfig =
        serde_json::from_str(&peers_str).expect("Failed to deserialize peers configuration");

    let threshold = peer_config.threshold();
    let polynomial = config.polynomial(threshold);

    info!(
        public_key = %config.signing_key.public_key(),
        share = ?config.share,
        ?polynomial,
        "Loaded participant configuration"
    );

    let p2p_namespace = union_unique(APPLICATION_NAMESPACE, b"_P2P");
    let mut p2p_cfg = discovery::Config::local(
        config.signing_key.clone(),
        &p2p_namespace,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        config.bootstrappers.clone().into_iter().collect::<Vec<_>>(),
        MAX_MESSAGE_SIZE,
    );
    p2p_cfg.mailbox_size = MAILBOX_SIZE;

    let (mut network, mut oracle) = discovery::Network::new(context.with_label("network"), p2p_cfg);

    // Register all possible peers
    oracle.register(0, peer_config.all_peers()).await;

    let pending_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

    let recovered_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

    let resolver_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

    let broadcaster_limit = Quota::per_second(NonZeroU32::new(8).unwrap());
    let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

    let backfill_quota = Quota::per_second(NonZeroU32::new(8).unwrap());
    let backfill = network.register(BACKFILL_BY_DIGEST_CHANNEL, backfill_quota, MESSAGE_BACKLOG);

    let dkg_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let dkg_channel = network.register(DKG_CHANNEL, dkg_limit, MESSAGE_BACKLOG);

    // Create a static resolver for backfill
    let coordinator = Coordinator::new(peer_config.all_peers());
    let resolver_cfg = p2p_resolver::Config {
        public_key: config.signing_key.public_key(),
        coordinator: coordinator.clone(),
        mailbox_size: 200,
        requester_config: requester::Config {
            public_key: config.signing_key.public_key(),
            rate_limit: Quota::per_second(NonZeroU32::new(8).unwrap()),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
        },
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let p2p_resolver = p2p_resolver::init(&context, resolver_cfg, backfill);

    let engine = engine::Engine::<_, _, _, Sha256, MinSig, S>::new(
        context.with_label("engine"),
        engine::Config {
            signer: config.signing_key.clone(),
            blocker: oracle,
            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
            participant_config: Some((args.config_path, config.clone())),
            polynomial,
            share: config.share,
            active_participants: peer_config.active,
            inactive_participants: peer_config.inactive,
            num_participants_per_epoch: peer_config.num_participants_per_epoch as usize,
            dkg_rate_limit: dkg_limit,
            partition_prefix: "engine".to_string(),
            freezer_table_initial_size: 1024 * 1024, // 100mb
        },
    )
    .await;

    let p2p_handle = network.start();
    let engine_handle = engine.start(
        pending,
        recovered,
        resolver,
        broadcaster,
        dkg_channel,
        p2p_resolver,
    );

    if let Err(e) = try_join_all(vec![p2p_handle, engine_handle]).await {
        error!(?e, "task failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        application::{Block, EdScheme, ThresholdScheme},
        BLOCKS_PER_EPOCH,
    };
    use commonware_consensus::marshal::ingress::handler;
    use commonware_cryptography::{
        bls12381::{dkg::ops, primitives::variant::MinSig},
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{self, Runner},
        Clock, Metrics, Runner as _, Spawner, Storage,
    };
    use commonware_utils::{quorum, sequence::U64, union};
    use futures::channel::mpsc;
    use governor::Quota;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroU32,
        time::Duration,
    };

    /// Registers all validators using the oracle.
    async fn register_validators(
        context: &deterministic::Context,
        oracle: &mut Oracle<PublicKey>,
        validators: &[PublicKey],
    ) -> HashMap<
        PublicKey,
        (
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
            (
                mpsc::Receiver<handler::Message<Block<Sha256, PrivateKey, MinSig>>>,
                commonware_resolver::p2p::Mailbox<
                    handler::Request<Block<Sha256, PrivateKey, MinSig>>,
                >,
            ),
        ),
    > {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (pending_sender, pending_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            let (resolver_sender, resolver_receiver) =
                oracle.register(validator.clone(), 2).await.unwrap();
            let (broadcast_sender, broadcast_receiver) =
                oracle.register(validator.clone(), 3).await.unwrap();
            let backfill = oracle.register(validator.clone(), 4).await.unwrap();
            let (dkg_sender, dkg_receiver) = oracle.register(validator.clone(), 5).await.unwrap();

            // Create a static resolver for backfill
            let coordinator = Coordinator::new(validators.to_vec());
            let resolver_cfg = p2p_resolver::Config {
                public_key: validator.clone(),
                coordinator: coordinator.clone(),
                mailbox_size: 200,
                requester_config: requester::Config {
                    public_key: validator.clone(),
                    rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            };
            let p2p_resolver = p2p_resolver::init(context, resolver_cfg, backfill);

            registrations.insert(
                validator.clone(),
                (
                    (pending_sender, pending_receiver),
                    (recovered_sender, recovered_receiver),
                    (resolver_sender, resolver_receiver),
                    (broadcast_sender, broadcast_receiver),
                    (dkg_sender, dkg_receiver),
                    p2p_resolver,
                ),
            );
        }
        registrations
    }

    /// Links (or unlinks) validators using the oracle.
    ///
    /// The `action` parameter determines the action (e.g. link, unlink) to take.
    /// The `restrict_to` function can be used to restrict the linking to certain connections,
    /// otherwise all validators will be linked to all other validators.
    async fn link_validators(
        oracle: &mut Oracle<PublicKey>,
        validators: &[PublicKey],
        link: Link,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                // Ignore self
                if v2 == v1 {
                    continue;
                }

                // Restrict to certain connections
                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }

                // Add link
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    fn all_online<S: Scheme>(n: u32, seed: u64, link: Link, required: u64) -> String
    where
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let threshold = quorum(n);
        let cfg = deterministic::Config::default().with_seed(seed);
        let executor = Runner::from(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    disconnect_on_block: true,
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n, threshold);

            // Register participants
            let mut signers = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let signer = PrivateKey::from_seed(i as u64);
                let pk = signer.public_key();
                signers.push(signer);
                validators.push(pk);
            }
            validators.sort();
            signers.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&context, &mut oracle, &validators).await;

            // Link all validators
            link_validators(&mut oracle, &validators, link, None).await;

            // Create instances
            let mut public_keys = HashSet::new();
            for (idx, signer) in signers.into_iter().enumerate() {
                let context = context.with_label(&format!("validator_{idx}"));

                // Create signer context
                let public_key = signer.public_key();
                public_keys.insert(public_key.clone());

                // Get networking
                let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                    registrations.remove(&public_key).unwrap();

                let engine = engine::Engine::<_, _, _, Sha256, MinSig, S>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer,
                        blocker: oracle.control(public_key),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: Some(shares[idx].clone()),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: validators.len(),
                        dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                        partition_prefix: format!("validator_{idx}"),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                    dkg_channel,
                );
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with contiguous_height, ensure it is at least required_container
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value >= required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }
            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_good_links_ed() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = all_online::<EdScheme>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<EdScheme>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced]
    fn test_good_links_threshold() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state =
                all_online::<ThresholdScheme<MinSig>>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<ThresholdScheme<MinSig>>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced]
    fn test_bad_links_ed() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.75,
        };
        for seed in 0..5 {
            let state = all_online::<EdScheme>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<EdScheme>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced]
    fn test_bad_links_threshold() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.75,
        };
        for seed in 0..5 {
            let state =
                all_online::<ThresholdScheme<MinSig>>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<ThresholdScheme<MinSig>>(5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced]
    #[ignore]
    fn test_1k() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online::<ThresholdScheme<MinSig>>(10, 0, link.clone(), 1000);
    }

    #[test_traced]
    fn test_reshare_failed() {
        // Create context
        let n = 6;
        let active = 4;
        let threshold = quorum(active);
        let initial_container_required = BLOCKS_PER_EPOCH / 2;
        let final_container_required = 2 * BLOCKS_PER_EPOCH + 1;
        let executor = Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, active, threshold);

            // Register participants
            let mut signers = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let signer = PrivateKey::from_seed(i as u64);
                let pk = signer.public_key();
                signers.push(signer);
                validators.push(pk);
            }
            validators.sort();
            signers.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&context, &mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, link.clone(), None).await;

            // Create instances
            let mut engine_handles = Vec::with_capacity(n as usize);
            for (idx, signer) in signers.iter().enumerate() {
                let public_key = signer.public_key();
                let share = if idx < active as usize {
                    Some(shares[idx].clone())
                } else {
                    None
                };
                let engine =
                    engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label("engine"),
                        engine::Config {
                            signer: signer.clone(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share,
                            active_participants: validators[..active as usize].to_vec(),
                            inactive_participants: validators[active as usize..].to_vec(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                let handle = engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                    dkg_channel,
                );
                engine_handles.push(handle);
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with contiguous_height, ensure it is at least required_container
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value > initial_container_required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_millis(10)).await;
            }

            // Bring all validators offline.
            for handle in engine_handles {
                handle.abort();
            }

            // Delete all metadata partitions, preventing actors from posting their deal outcomes to the chain.
            for i in 0..n {
                let partition = format!("validator_{i}_dkg_rounds");

                context.remove(&partition, None).await.unwrap();
                context
                    .open(&partition, U64::from(0).as_ref())
                    .await
                    .unwrap();
            }

            // Create new simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            let mut registrations = register_validators(&context, &mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, link.clone(), None).await;

            // Bring all validators back online.
            for (idx, signer) in signers.iter().enumerate() {
                let public_key = signer.public_key();
                let share = if idx < active as usize {
                    Some(shares[idx].clone())
                } else {
                    None
                };
                let engine =
                    engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label("engine"),
                        engine::Config {
                            signer: signer.clone(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share,
                            active_participants: validators[..active as usize].to_vec(),
                            inactive_participants: validators[active as usize..].to_vec(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                    dkg_channel,
                );
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with contiguous_height, ensure it is at least required_container
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value >= final_container_required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_millis(10)).await;
            }

            // Ensure validators saw the round fail.
            let metrics = context.encode();
            let round_failed = metrics.lines().any(|l| {
                let mut parts = l.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                metric.ends_with("_failed_rounds_total") && value.parse::<u64>().unwrap() == 1
            });
            assert!(round_failed);
        });
    }

    fn test_backfill<S: Scheme>()
    where
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let initial_container_required = BLOCKS_PER_EPOCH / 2 + 1;
        let final_container_required = 2 * BLOCKS_PER_EPOCH + 1;
        let executor = Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n, threshold);

            // Register participants
            let mut signers = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let signer = PrivateKey::from_seed(i as u64);
                let pk = signer.public_key();
                signers.push(signer);
                validators.push(pk);
            }
            validators.sort();
            signers.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&context, &mut oracle, &validators).await;

            // Link all validators (except 0)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                link.clone(),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create instances
            for (idx, signer) in signers.iter().enumerate() {
                // Skip first
                if idx == 0 {
                    continue;
                }

                let public_key = signer.public_key();
                let engine = engine::Engine::<_, _, _, Sha256, MinSig, S>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer: signer.clone(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: Some(shares[idx].clone()),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: validators.len(),
                        dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                        partition_prefix: format!("validator_{idx}"),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                    dkg_channel,
                );
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with contiguous_height, ensure it is at least required_container
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value >= initial_container_required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }

            // Link first peer
            link_validators(
                &mut oracle,
                &validators,
                link,
                Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
            )
            .await;

            let signer = signers[0].clone();
            let share = shares[0].clone();
            let public_key = signer.public_key();
            let engine = engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                context.with_label("engine"),
                engine::Config {
                    signer: signer.clone(),
                    blocker: oracle.control(public_key.clone()),
                    namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                    participant_config: None,
                    polynomial: Some(polynomial.clone()),
                    share: Some(share),
                    active_participants: validators.clone(),
                    inactive_participants: Vec::default(),
                    num_participants_per_epoch: validators.len(),
                    dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                    partition_prefix: "validator_0".to_string(),
                    freezer_table_initial_size: 1024, // 1mb
                },
            )
            .await;

            // Get networking
            let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                backfill,
                dkg_channel,
            );

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with contiguous_height, ensure it is at least required_container
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value >= final_container_required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }
        });
    }

    #[test_traced]
    fn test_backfill_ed() {
        test_backfill::<EdScheme>();
    }

    #[test_traced]
    fn test_backfill_threshold() {
        test_backfill::<ThresholdScheme<MinSig>>();
    }

    fn test_backfill_multi_epoch<S: Scheme>()
    where
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let initial_container_required = BLOCKS_PER_EPOCH + (BLOCKS_PER_EPOCH / 2);
        let final_container_required = 4 * BLOCKS_PER_EPOCH + 1;
        let executor = Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n, threshold);

            // Register participants
            let mut signers = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let signer = PrivateKey::from_seed(i as u64);
                let pk = signer.public_key();
                signers.push(signer);
                validators.push(pk);
            }
            validators.sort();
            signers.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&context, &mut oracle, &validators).await;

            // Link all validators (except 0)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                link.clone(),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create instances
            for (idx, signer) in signers.iter().enumerate() {
                // Skip first
                if idx == 0 {
                    continue;
                }

                let public_key = signer.public_key();
                let engine =
                    engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label(&format!("engine_{idx}")),
                        engine::Config {
                            signer: signer.clone(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share: Some(shares[idx].clone()),
                            active_participants: validators.clone(),
                            inactive_participants: Vec::default(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                    dkg_channel,
                );
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = false;
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with processed_height, ensure it is at least initial_container_required
                    if metric.ends_with("_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if value >= initial_container_required {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }

            // Link first peer
            link_validators(
                &mut oracle,
                &validators,
                link,
                Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
            )
            .await;

            let signer = signers[0].clone();
            let share = shares[0].clone();
            let public_key = signer.public_key();
            let engine = engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                context.with_label("engine_0"),
                engine::Config {
                    signer: signer.clone(),
                    blocker: oracle.control(public_key.clone()),
                    namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                    participant_config: None,
                    polynomial: Some(polynomial.clone()),
                    share: Some(share),
                    active_participants: validators.clone(),
                    inactive_participants: Vec::default(),
                    num_participants_per_epoch: validators.len(),
                    dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                    partition_prefix: "validator_0".to_string(),
                    freezer_table_initial_size: 1024, // 1mb
                },
            )
            .await;

            // Get networking
            let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                backfill,
                dkg_channel,
            );

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut completed_validators = HashSet::new();
                for line in metrics.lines() {
                    // Split metric and value
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    // If ends with peers_blocked, ensure it is zero
                    if metric.ends_with("_peers_blocked") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    if metric.ends_with("_failed_rounds_total") {
                        let value = value.parse::<u64>().unwrap();
                        assert_eq!(value, 0);
                    }

                    // If ends with processed_height, ensure it is at least final_container_required
                    for idx in 0..n {
                        if metric.contains(&format!("engine_{idx}"))
                            && metric.ends_with("_processed_height")
                        {
                            let value = value.parse::<u64>().unwrap();
                            if value >= final_container_required {
                                completed_validators.insert(idx);
                                break;
                            }
                        }
                    }
                }

                if completed_validators.len() == n as usize {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }
        });
    }

    #[test_traced]
    fn test_backfill_multi_epoch_ed() {
        test_backfill_multi_epoch::<EdScheme>();
    }

    #[test_traced]
    fn test_backfill_multi_epoch_threshold() {
        test_backfill_multi_epoch::<ThresholdScheme<MinSig>>();
    }

    fn test_unclean_shutdown<S: Scheme>()
    where
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_container = 2 * BLOCKS_PER_EPOCH + 1;

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, threshold);

        // Random restarts every x seconds
        let mut runs = 0;
        let mut prev_ctx = None;
        loop {
            // Setup run
            let polynomial = polynomial.clone();
            let shares = shares.clone();
            let f = |mut context: deterministic::Context| async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                    },
                );

                // Start network
                network.start();

                // Register participants
                let mut signers = Vec::new();
                let mut validators = Vec::new();
                for i in 0..n {
                    let signer = PrivateKey::from_seed(i as u64);
                    let pk = signer.public_key();
                    signers.push(signer);
                    validators.push(pk);
                }
                validators.sort();
                signers.sort_by_key(|s| s.public_key());
                let mut registrations =
                    register_validators(&context, &mut oracle, &validators).await;

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &validators, link, None).await;

                // Create instances
                let mut public_keys = HashSet::new();
                for (idx, signer) in signers.into_iter().enumerate() {
                    // Create signer context
                    let public_key = signer.public_key();
                    public_keys.insert(public_key.clone());

                    let engine =
                        engine::Engine::<_, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                            context.with_label("engine"),
                            engine::Config {
                                signer: signer.clone(),
                                blocker: oracle.control(public_key.clone()),
                                namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                                participant_config: None,
                                polynomial: Some(polynomial.clone()),
                                share: Some(shares[idx].clone()),
                                active_participants: validators.clone(),
                                inactive_participants: Vec::default(),
                                num_participants_per_epoch: validators.len(),
                                dkg_rate_limit: Quota::per_second(NonZeroU32::new(128).unwrap()),
                                partition_prefix: format!("validator_{idx}"),
                                freezer_table_initial_size: 1024, // 1mb
                            },
                        )
                        .await;

                    // Get networking
                    let (pending, recovered, resolver, broadcast, backfill, dkg_channel) =
                        registrations.remove(&public_key).unwrap();

                    // Start engine
                    engine.start(
                        pending,
                        recovered,
                        resolver,
                        broadcast,
                        backfill,
                        dkg_channel,
                    );
                }

                // Poll metrics
                let poller = context
                    .with_label("metrics")
                    .spawn(move |context| async move {
                        loop {
                            let metrics = context.encode();

                            // Iterate over all lines
                            let mut success = false;
                            for line in metrics.lines() {
                                // Split metric and value
                                let mut parts = line.split_whitespace();
                                let metric = parts.next().unwrap();
                                let value = parts.next().unwrap();

                                // If ends with peers_blocked, ensure it is zero
                                if metric.ends_with("_peers_blocked") {
                                    let value = value.parse::<u64>().unwrap();
                                    assert_eq!(value, 0);
                                }

                                // If ends with contiguous_height, ensure it is at least required_container
                                if metric.ends_with("_processed_height") {
                                    let value = value.parse::<u64>().unwrap();
                                    if value >= required_container {
                                        success = true;
                                        break;
                                    }
                                }
                            }
                            if success {
                                break;
                            }

                            // Still waiting for all validators to complete
                            context.sleep(Duration::from_millis(10)).await;
                        }
                    });

                // Exit at random points until finished
                let wait =
                    context.gen_range(Duration::from_millis(100)..Duration::from_millis(1_000));

                // Wait for one to finish
                select! {
                    _ = poller => {
                        // Finished
                        true
                    },
                    _ = context.sleep(wait) => {
                        // Randomly exit
                        false
                    }
                }
            };

            // Handle run
            let (complete, checkpoint) = if let Some(prev_checkpoint) = prev_ctx {
                Runner::from(prev_checkpoint)
            } else {
                Runner::timed(Duration::from_secs(30))
            }
            .start_and_recover(f);
            if complete {
                break;
            }

            // Prepare for next run
            prev_ctx = Some(checkpoint);
            runs += 1;
        }
        assert!(runs > 1);
    }

    #[test_traced]
    fn test_unclean_shutdown_ed() {
        test_unclean_shutdown::<EdScheme>();
    }

    #[test_traced]
    fn test_unclean_shutdown_threshold() {
        test_unclean_shutdown::<ThresholdScheme<MinSig>>();
    }
}
