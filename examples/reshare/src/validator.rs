//! Validator node service entrypoint.

use crate::{
    application::{EpochSchemeProvider, SchemeProvider},
    engine,
    setup::{ParticipantConfig, PeerConfig},
};
use commonware_consensus::{
    marshal::resolver::p2p as marshal_resolver, simplex::signing_scheme::Scheme,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, Sha256, Signer};
use commonware_p2p::{authenticated::discovery, utils::requester};
use commonware_runtime::{tokio, Metrics};
use commonware_utils::{union, union_unique, NZU32};
use futures::future::try_join_all;
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::{error, info};

const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_RESHARE";

const PENDING_CHANNEL: u64 = 0;
const RECOVERED_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BROADCASTER_CHANNEL: u64 = 3;
const MARSHAL_CHANNEL: u64 = 4;
const DKG_CHANNEL: u64 = 5;
const ORCHESTRATOR_CHANNEL: u64 = 6;

const MAILBOX_SIZE: usize = 10;
const MESSAGE_BACKLOG: usize = 10;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Run the validator node service.
pub async fn run<S>(context: tokio::Context, args: super::ParticipantArgs)
where
    S: Scheme<PublicKey = ed25519::PublicKey>,
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

    let (mut network, oracle) = discovery::Network::new(context.with_label("network"), p2p_cfg);

    let pending_limit = Quota::per_second(NZU32!(128));
    let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

    let recovered_limit = Quota::per_second(NZU32!(128));
    let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

    let resolver_limit = Quota::per_second(NZU32!(128));
    let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

    let broadcaster_limit = Quota::per_second(NZU32!(8));
    let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

    let marshal_limit = Quota::per_second(NZU32!(8));
    let marshal = network.register(MARSHAL_CHANNEL, marshal_limit, MESSAGE_BACKLOG);

    let orchestrator_limit = Quota::per_second(NZU32!(1));
    let orchestrator = network.register(ORCHESTRATOR_CHANNEL, orchestrator_limit, MESSAGE_BACKLOG);

    let dkg_limit = Quota::per_second(NZU32!(128));
    let dkg = network.register(DKG_CHANNEL, dkg_limit, MESSAGE_BACKLOG);

    // Create a static resolver for marshal
    let resolver_cfg = marshal_resolver::Config {
        public_key: config.signing_key.public_key(),
        manager: oracle.clone(),
        mailbox_size: 200,
        requester_config: requester::Config {
            me: Some(config.signing_key.public_key()),
            rate_limit: marshal_limit,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
        },
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let marshal = marshal_resolver::init(&context, resolver_cfg, marshal);

    let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
        context.with_label("engine"),
        engine::Config {
            signer: config.signing_key.clone(),
            manager: oracle.clone(),
            blocker: oracle.clone(),
            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
            participant_config: Some((args.config_path, config.clone())),
            polynomial,
            share: config.share,
            active_participants: peer_config.active,
            inactive_participants: peer_config.inactive,
            num_participants_per_epoch: peer_config.num_participants_per_epoch as usize,
            dkg_rate_limit: dkg_limit,
            orchestrator_rate_limit: orchestrator_limit,
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
        dkg,
        orchestrator,
        marshal,
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
        time::Duration,
    };

    async fn register_validator(
        context: &deterministic::Context,
        oracle: &mut Oracle<PublicKey>,
        validator: PublicKey,
    ) -> (
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (
            mpsc::Receiver<handler::Message<Block<Sha256, PrivateKey, MinSig>>>,
            commonware_resolver::p2p::Mailbox<handler::Request<Block<Sha256, PrivateKey, MinSig>>>,
        ),
    ) {
        let mut control = oracle.control(validator.clone());
        let pending = control.register(PENDING_CHANNEL).await.unwrap();
        let recovered = control.register(RECOVERED_CHANNEL).await.unwrap();
        let resolver = control.register(RESOLVER_CHANNEL).await.unwrap();
        let broadcast = control.register(BROADCASTER_CHANNEL).await.unwrap();
        let marshal = control.register(MARSHAL_CHANNEL).await.unwrap();
        let dkg = control.register(DKG_CHANNEL).await.unwrap();
        let orchestrator = control.register(ORCHESTRATOR_CHANNEL).await.unwrap();

        let resolver_cfg = marshal_resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            mailbox_size: 200,
            requester_config: requester::Config {
                me: Some(validator),
                rate_limit: Quota::per_second(NZU32!(5)),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let marshal = marshal_resolver::init(context, resolver_cfg, marshal);

        (
            pending,
            recovered,
            resolver,
            broadcast,
            dkg,
            orchestrator,
            marshal,
        )
    }

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
            let registration = register_validator(context, oracle, validator.clone()).await;
            registrations.insert(validator.clone(), registration);
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

    fn all_online<S>(n: u32, n_active: u32, seed: u64, link: Link, required: u64) -> String
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let threshold = quorum(n_active);
        let cfg = deterministic::Config::default().with_seed(seed);
        let executor = Runner::from(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n_active, threshold);

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
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer,
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: shares.get(idx).cloned(),
                        active_participants: validators[..n_active as usize].to_vec(),
                        inactive_participants: validators[n_active as usize..].to_vec(),
                        num_participants_per_epoch: n_active as usize,
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
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
                    dkg,
                    orchestrator,
                    marshal,
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

    #[test_traced("INFO")]
    #[ignore]
    fn test_good_links_ed() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = all_online::<EdScheme>(5, 5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<EdScheme>(5, 5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_good_links_threshold() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = all_online::<ThresholdScheme<MinSig>>(
                5,
                5,
                seed,
                link.clone(),
                BLOCKS_PER_EPOCH + 1,
            );
            assert_eq!(
                state,
                all_online::<ThresholdScheme<MinSig>>(
                    5,
                    5,
                    seed,
                    link.clone(),
                    BLOCKS_PER_EPOCH + 1
                )
            );
        }
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_bad_links_ed() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.75,
        };
        for seed in 0..5 {
            let state = all_online::<EdScheme>(5, 5, seed, link.clone(), BLOCKS_PER_EPOCH + 1);
            assert_eq!(
                state,
                all_online::<EdScheme>(5, 5, seed, link.clone(), BLOCKS_PER_EPOCH + 1)
            );
        }
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_bad_links_threshold() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.75,
        };
        for seed in 0..5 {
            let state = all_online::<ThresholdScheme<MinSig>>(
                5,
                5,
                seed,
                link.clone(),
                BLOCKS_PER_EPOCH + 1,
            );
            assert_eq!(
                state,
                all_online::<ThresholdScheme<MinSig>>(
                    5,
                    5,
                    seed,
                    link.clone(),
                    BLOCKS_PER_EPOCH + 1
                )
            );
        }
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_1k() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online::<ThresholdScheme<MinSig>>(10, 10, 0, link.clone(), 1000);
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_1k_rotate() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online::<ThresholdScheme<MinSig>>(10, 4, 0, link.clone(), 1000);
    }

    fn reshare_failed(seed: u64) -> String {
        // Create context
        let n = 6;
        let active = 4;
        let threshold = quorum(active);
        let initial_container_required = BLOCKS_PER_EPOCH / 2;
        let final_container_required = 2 * BLOCKS_PER_EPOCH + 1;
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let executor = Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
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
                    engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label("engine"),
                        engine::Config {
                            signer: signer.clone(),
                            manager: oracle.manager(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share,
                            active_participants: validators[..active as usize].to_vec(),
                            inactive_participants: validators[active as usize..].to_vec(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NZU32!(128)),
                            orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                let handle = engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
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
                    tracked_peer_sets: Some(3),
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
                    engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label("engine"),
                        engine::Config {
                            signer: signer.clone(),
                            manager: oracle.manager(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share,
                            active_participants: validators[..active as usize].to_vec(),
                            inactive_participants: validators[active as usize..].to_vec(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NZU32!(128)),
                            orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
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

            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_reshare_failed() {
        assert_eq!(reshare_failed(1), reshare_failed(1));
    }

    fn test_marshal<S>(seed: u64) -> String
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let initial_container_required = BLOCKS_PER_EPOCH / 2 + 1;
        let final_container_required = 2 * BLOCKS_PER_EPOCH + 1;
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let executor = Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
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
                let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer: signer.clone(),
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: Some(shares[idx].clone()),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: validators.len(),
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: format!("validator_{idx}"),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
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
            let engine =
                engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer: signer.clone(),
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: Some(share),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: validators.len(),
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: "validator_0".to_string(),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

            // Get networking
            let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                dkg,
                orchestrator,
                marshal,
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

            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_ed() {
        assert_eq!(test_marshal::<EdScheme>(1), test_marshal::<EdScheme>(1));
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_threshold() {
        assert_eq!(
            test_marshal::<ThresholdScheme<MinSig>>(1),
            test_marshal::<ThresholdScheme<MinSig>>(1)
        );
    }

    fn test_marshal_multi_epoch<S>(seed: u64) -> String
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let initial_container_required = BLOCKS_PER_EPOCH + (BLOCKS_PER_EPOCH / 2);
        let final_container_required = 4 * BLOCKS_PER_EPOCH + 1;
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let executor = Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
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
                    engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label(&format!("engine_{idx}")),
                        engine::Config {
                            signer: signer.clone(),
                            manager: oracle.manager(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share: Some(shares[idx].clone()),
                            active_participants: validators.clone(),
                            inactive_participants: Vec::default(),
                            num_participants_per_epoch: validators.len(),
                            dkg_rate_limit: Quota::per_second(NZU32!(128)),
                            orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
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
            let engine =
                engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                    context.with_label("engine_0"),
                    engine::Config {
                        signer: signer.clone(),
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: Some(share),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: validators.len(),
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: "validator_0".to_string(),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

            // Get networking
            let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                dkg,
                orchestrator,
                marshal,
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

            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_multi_epoch_ed() {
        assert_eq!(
            test_marshal_multi_epoch::<EdScheme>(1),
            test_marshal_multi_epoch::<EdScheme>(1)
        );
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_multi_epoch_threshold() {
        assert_eq!(
            test_marshal_multi_epoch::<ThresholdScheme<MinSig>>(1),
            test_marshal_multi_epoch::<ThresholdScheme<MinSig>>(1)
        );
    }

    fn test_marshal_multi_epoch_non_member_of_committee<S: Scheme>(seed: u64) -> String
    where
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n - 1);
        let initial_container_required = BLOCKS_PER_EPOCH + (BLOCKS_PER_EPOCH / 2);
        let final_container_required = 4 * BLOCKS_PER_EPOCH + 1;
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let executor = Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );

            // Start network
            network.start();

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n - 1, threshold);

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
                    engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                        context.with_label(&format!("engine_{idx}")),
                        engine::Config {
                            signer: signer.clone(),
                            manager: oracle.manager(),
                            blocker: oracle.control(public_key.clone()),
                            namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                            participant_config: None,
                            polynomial: Some(polynomial.clone()),
                            share: Some(shares[idx - 1].clone()),
                            active_participants: validators[1..].to_vec(),
                            inactive_participants: validators[..1].to_vec(),
                            num_participants_per_epoch: validators.len() - 1,
                            dkg_rate_limit: Quota::per_second(NZU32!(128)),
                            orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                            partition_prefix: format!("validator_{idx}"),
                            freezer_table_initial_size: 1024, // 1mb
                        },
                    )
                    .await;

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                // Start engine
                engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
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

            // Set up the peer to marshal. Note that this peer is _not_ a part of the committee
            // in the first epoch.
            let signer = signers[0].clone();
            let public_key = signer.public_key();
            let engine =
                engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                    context.with_label("engine_0"),
                    engine::Config {
                        signer: signer.clone(),
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: None,
                        active_participants: validators[1..].to_vec(),
                        inactive_participants: validators[..1].to_vec(),
                        num_participants_per_epoch: validators.len() - 1,
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: "validator_0".to_string(),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

            // Get networking
            let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                broadcast,
                dkg,
                orchestrator,
                marshal,
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
            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_multi_epoch_non_member_of_committee_ed() {
        assert_eq!(
            test_marshal_multi_epoch_non_member_of_committee::<EdScheme>(1),
            test_marshal_multi_epoch_non_member_of_committee::<EdScheme>(1)
        );
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_marshal_multi_epoch_non_member_of_committee_threshold() {
        assert_eq!(
            test_marshal_multi_epoch_non_member_of_committee::<ThresholdScheme<MinSig>>(1),
            test_marshal_multi_epoch_non_member_of_committee::<ThresholdScheme<MinSig>>(1)
        );
    }

    fn test_unclean_shutdown<S>(seed: u64) -> String
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        SchemeProvider<S, ed25519::PrivateKey>:
            EpochSchemeProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
    {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_container = 2 * BLOCKS_PER_EPOCH + 1;

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(seed);
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
                        tracked_peer_sets: Some(3),
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
                        engine::Engine::<_, _, _, _, Sha256, MinSig, ThresholdScheme<MinSig>>::new(
                            context.with_label("engine"),
                            engine::Config {
                                signer: signer.clone(),
                                manager: oracle.manager(),
                                blocker: oracle.control(public_key.clone()),
                                namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                                participant_config: None,
                                polynomial: Some(polynomial.clone()),
                                share: Some(shares[idx].clone()),
                                active_participants: validators.clone(),
                                inactive_participants: Vec::default(),
                                num_participants_per_epoch: validators.len(),
                                dkg_rate_limit: Quota::per_second(NZU32!(128)),
                                orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                                partition_prefix: format!("validator_{idx}"),
                                freezer_table_initial_size: 1024, // 1mb
                            },
                        )
                        .await;

                    // Get networking
                    let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                        registrations.remove(&public_key).unwrap();

                    // Start engine
                    engine.start(
                        pending,
                        recovered,
                        resolver,
                        broadcast,
                        dkg,
                        orchestrator,
                        marshal,
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
                    context.gen_range(Duration::from_millis(500)..Duration::from_millis(1_000));

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
                let cfg = deterministic::Config::default()
                    .with_seed(seed)
                    .with_timeout(Some(Duration::from_secs(180)));
                Runner::new(cfg)
            }
            .start_and_recover(f);

            // If complete, break out of the loop
            prev_ctx = Some(checkpoint);
            if complete {
                break;
            }
            runs += 1;
        }
        assert!(runs > 1);

        prev_ctx.expect("no previous context").auditor().state()
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_unclean_shutdown_ed() {
        assert_eq!(
            test_unclean_shutdown::<EdScheme>(1),
            test_unclean_shutdown::<EdScheme>(1)
        );
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_unclean_shutdown_threshold() {
        assert_eq!(
            test_unclean_shutdown::<ThresholdScheme<MinSig>>(1),
            test_unclean_shutdown::<ThresholdScheme<MinSig>>(1)
        );
    }

    fn restart<S>(
        n: u32,
        seed: u64,
        link: Link,
        shutdown_height: u64,
        restart_height: u64,
        final_required: u64,
    ) -> String
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
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
                    tracked_peer_sets: Some(3),
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
            let mut engines = Vec::new();
            let mut public_keys = HashSet::new();
            for (idx, signer) in signers.iter().enumerate() {
                let context = context.with_label(&format!("validator_{idx}"));

                // Create signer context
                let public_key = signer.public_key();
                public_keys.insert(public_key.clone());

                // Get networking
                let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                    registrations.remove(&public_key).unwrap();

                let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                    context.with_label("engine"),
                    engine::Config {
                        signer: signer.clone(),
                        manager: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        participant_config: None,
                        polynomial: Some(polynomial.clone()),
                        share: shares.get(idx).cloned(),
                        active_participants: validators.clone(),
                        inactive_participants: Vec::default(),
                        num_participants_per_epoch: n as usize,
                        dkg_rate_limit: Quota::per_second(NZU32!(128)),
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: format!("validator_{idx}"),
                        freezer_table_initial_size: 1024, // 1mb
                    },
                )
                .await;

                let handle = engine.start(
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    dkg,
                    orchestrator,
                    marshal,
                );
                engines.push(handle);
            }

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = 0;
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
                        if value >= shutdown_height {
                            success += 1;
                        }
                    }
                }
                if success == n {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }

            // Abort a validator
            let idx = context.gen_range(0..engines.len());
            let signer = signers[idx].clone();
            let public_key = signer.public_key();
            let handle = engines.remove(idx);
            handle.abort();
            info!(idx, ?public_key, "aborted validator");

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = 0;
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
                        if value >= restart_height {
                            success += 1;
                        }
                    }
                }
                if success == n - 1 {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }

            // Get networking
            let context = context.with_label(&format!("validator_{idx}_restarted"));
            let (pending, recovered, resolver, broadcast, dkg, orchestrator, marshal) =
                register_validator(&context, &mut oracle, public_key.clone()).await;

            let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                context.with_label("engine"),
                engine::Config {
                    signer: signer.clone(),
                    manager: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                    participant_config: None,
                    polynomial: Some(polynomial.clone()),
                    share: shares.get(idx).cloned(),
                    active_participants: validators,
                    inactive_participants: Vec::default(),
                    num_participants_per_epoch: n as usize,
                    dkg_rate_limit: Quota::per_second(NZU32!(128)),
                    orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
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
                dkg,
                orchestrator,
                marshal,
            );
            info!(idx, ?public_key, "restarted validator");

            // Poll metrics
            loop {
                let metrics = context.encode();

                // Iterate over all lines
                let mut success = 0;
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
                        if value >= final_required {
                            success += 1;
                        }
                    }
                }
                if success == n {
                    break;
                }

                // Still waiting for all validators to complete
                context.sleep(Duration::from_secs(1)).await;
            }

            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_restart_ed() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = restart::<EdScheme>(
                5,
                seed,
                link.clone(),
                BLOCKS_PER_EPOCH + 1,
                2 * BLOCKS_PER_EPOCH + 1,
                3 * BLOCKS_PER_EPOCH + 1,
            );
            assert_eq!(
                state,
                restart::<EdScheme>(
                    5,
                    seed,
                    link.clone(),
                    BLOCKS_PER_EPOCH + 1,
                    2 * BLOCKS_PER_EPOCH + 1,
                    3 * BLOCKS_PER_EPOCH + 1
                )
            );
        }
    }

    #[test_traced("INFO")]
    #[ignore]
    fn test_restart_threshold() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = restart::<ThresholdScheme<MinSig>>(
                5,
                seed,
                link.clone(),
                BLOCKS_PER_EPOCH + 1,
                2 * BLOCKS_PER_EPOCH + 1,
                3 * BLOCKS_PER_EPOCH + 1,
            );
            assert_eq!(
                state,
                restart::<ThresholdScheme<MinSig>>(
                    5,
                    seed,
                    link.clone(),
                    BLOCKS_PER_EPOCH + 1,
                    2 * BLOCKS_PER_EPOCH + 1,
                    3 * BLOCKS_PER_EPOCH + 1
                )
            );
        }
    }
}
