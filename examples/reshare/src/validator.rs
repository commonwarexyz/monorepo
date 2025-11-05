//! Validator node service entrypoint.

use crate::{
    application::{EpochSchemeProvider, SchemeProvider},
    dkg::UpdateCallBack,
    engine,
    setup::{ParticipantConfig, PeerConfig},
};
use commonware_consensus::{
    marshal::resolver::p2p as marshal_resolver, simplex::signing_scheme::Scheme,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, Sha256, Signer};
use commonware_p2p::{authenticated::discovery, utils::requester, Manager as _};
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
pub async fn run<S>(
    context: tokio::Context,
    args: super::ParticipantArgs,
    update_cb: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
) where
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
    let output = config.output(threshold);

    info!(
        public_key = %config.signing_key.public_key(),
        share = ?config.share,
        ?output,
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
    oracle.update(0, peer_config.participants.clone()).await;

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
        blocker: oracle.clone(),
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
            output: output,
            share: config.share,
            orchestrator_rate_limit: orchestrator_limit,
            partition_prefix: "engine".to_string(),
            freezer_table_initial_size: 1024 * 1024, // 100mb
            peer_config,
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
        update_cb,
    );

    if let Err(e) = try_join_all(vec![p2p_handle, engine_handle]).await {
        error!(?e, "task failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        application::{EdScheme, ThresholdScheme},
        dkg::{PostUpdate, Update},
    };
    use anyhow::anyhow;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        bls12381::{
            dkg2::{deal, Output},
            primitives::{group::Share, variant::MinSig},
        },
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt, Signer,
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_p2p::simulated::{self, Link, Network, Oracle};
    use commonware_runtime::{
        deterministic::{self, Runner},
        Runner as _,
    };
    use commonware_utils::union;
    use futures::{
        channel::{mpsc, oneshot},
        SinkExt, StreamExt,
    };
    use governor::Quota;
    use rand_core::CryptoRngCore;
    use std::{
        collections::{BTreeMap, HashMap},
        future::Future,
        pin::Pin,
        time::Duration,
    };

    struct TeamUpdate {
        pk: PublicKey,
        update: Update<MinSig, PublicKey>,
        cb_in: oneshot::Sender<PostUpdate>,
    }

    struct UpdateHandler {
        pk: PublicKey,
        sender: mpsc::Sender<TeamUpdate>,
    }

    impl UpdateHandler {
        fn boxed(pk: PublicKey, sender: mpsc::Sender<TeamUpdate>) -> Box<Self> {
            Box::new(Self { pk, sender })
        }
    }

    impl UpdateCallBack<MinSig, PublicKey> for UpdateHandler {
        fn on_update(
            &mut self,
            update: Update<MinSig, PublicKey>,
        ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>> {
            let mut sender = self.sender.clone();
            let pk = self.pk.clone();
            Box::pin(async move {
                let (cb_in, cb_out) = oneshot::channel();
                if !sender.send(TeamUpdate { pk, update, cb_in }).await.is_ok() {
                    return PostUpdate::Stop;
                };
                cb_out.await.unwrap_or(PostUpdate::Stop)
            })
        }
    }

    #[derive(Clone)]
    struct Team {
        peer_config: PeerConfig,
        output: Output<MinSig, PublicKey>,
        participants: BTreeMap<PublicKey, (PrivateKey, Option<Share>)>,
    }

    impl Team {
        fn reckon(mut rng: impl CryptoRngCore, total: u32, per_round: u32) -> Self {
            let mut participants = (0..total)
                .map(|i| {
                    let sk = PrivateKey::from_seed(i as u64);
                    (sk.public_key(), (sk, None::<Share>))
                })
                .collect::<BTreeMap<_, _>>();
            let peer_config = PeerConfig {
                num_participants_per_epoch: per_round,
                participants: participants.keys().cloned().collect(),
            };
            let (output, shares) = deal(&mut rng, peer_config.dealers(0));
            for (key, share) in shares.into_iter() {
                participants.get_mut(&key).map(|x| x.1 = Some(share));
            }
            Self {
                peer_config,
                output,
                participants,
            }
        }

        async fn start<S>(
            self,
            ctx: deterministic::Context,
            mut oracle: Oracle<PublicKey>,
            link: Link,
            updates: mpsc::Sender<TeamUpdate>,
        ) where
            S: Scheme<PublicKey = PublicKey>,
            SchemeProvider<S, PrivateKey>:
                EpochSchemeProvider<Variant = MinSig, PublicKey = PublicKey, Scheme = S>,
        {
            // First register all participants with oracle
            let mut manager = oracle.manager();
            manager
                .update(0, self.participants.keys().cloned().collect())
                .await;

            // Register channels for all participants first
            let mut channels = HashMap::new();
            for pk in self.participants.keys() {
                let mut control = oracle.control(pk.clone());
                let pending = control.register(PENDING_CHANNEL).await.unwrap();
                let recovered = control.register(RECOVERED_CHANNEL).await.unwrap();
                let resolver = control.register(RESOLVER_CHANNEL).await.unwrap();
                let broadcast = control.register(BROADCASTER_CHANNEL).await.unwrap();
                let marshal = control.register(MARSHAL_CHANNEL).await.unwrap();
                let dkg = control.register(DKG_CHANNEL).await.unwrap();
                let orchestrator = control.register(ORCHESTRATOR_CHANNEL).await.unwrap();

                channels.insert(
                    pk.clone(),
                    (
                        pending,
                        recovered,
                        resolver,
                        broadcast,
                        marshal,
                        dkg,
                        orchestrator,
                    ),
                );
            }

            // Now add links between all participants
            for v1 in self.participants.keys() {
                for v2 in self.participants.keys() {
                    if v1 == v2 {
                        continue;
                    }
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }

            // Now start all the engines
            for (i, (pk, (sk, share))) in self.participants.into_iter().enumerate() {
                let (pending, recovered, resolver, broadcast, marshal, dkg, orchestrator) =
                    channels.remove(&pk).unwrap();

                let resolver_cfg = marshal_resolver::Config {
                    public_key: pk.clone(),
                    manager: manager.clone(),
                    blocker: oracle.control(pk.clone()),
                    mailbox_size: 200,
                    requester_config: requester::Config {
                        me: Some(pk.clone()),
                        rate_limit: Quota::per_second(NZU32!(5)),
                        initial: Duration::from_secs(1),
                        timeout: Duration::from_secs(2),
                    },
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                };
                let marshal = marshal_resolver::init(&ctx, resolver_cfg, marshal);

                let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                    ctx.with_label(&format!("validator_{i}")),
                    engine::Config {
                        signer: sk,
                        manager: manager.clone(),
                        blocker: oracle.control(pk.clone()),
                        namespace: union(APPLICATION_NAMESPACE, b"_ENGINE"),
                        output: Some(self.output.clone()),
                        share: share,
                        orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                        partition_prefix: format!("validator_{i}"),
                        freezer_table_initial_size: 1024, // 1mb
                        peer_config: self.peer_config.clone(),
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
                    UpdateHandler::boxed(pk, updates.clone()),
                );
            }
        }
    }

    struct Plan {
        seed: u64,
        total: u32,
        per_round: u32,
        link: Link,
        target: u64,
    }

    impl Plan {
        async fn run_inner<S>(self, mut ctx: deterministic::Context) -> anyhow::Result<()>
        where
            S: Scheme<PublicKey = PublicKey>,
            SchemeProvider<S, PrivateKey>:
                EpochSchemeProvider<Variant = MinSig, PublicKey = PublicKey, Scheme = S>,
        {
            tracing::info!("starting test with {} participants", self.total);
            // Create simulated network
            let (network, oracle) = Network::<_, PublicKey>::new(
                ctx.with_label("network"),
                simulated::Config {
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                    max_size: 1024 * 1024,
                },
            );

            // Start network first to ensure a background task is running
            tracing::debug!("starting network actor");
            network.start();

            tracing::debug!("creating team with {} participants", self.total);
            let team = Team::reckon(&mut ctx, self.total, self.per_round);

            let (updates_in, mut updates_out) = mpsc::channel(0);

            tracing::debug!("starting team actors and connecting");
            team.start::<S>(ctx.clone(), oracle, self.link.clone(), updates_in)
                .await;

            tracing::debug!("waiting for updates");
            let mut outputs = Vec::<Option<Output<MinSig, PublicKey>>>::new();
            let mut status = BTreeMap::<PublicKey, Epoch>::new();
            let mut current_epoch = Epoch::zero();
            let mut successes = 0u64;
            while let Some(update) = updates_out.next().await {
                let (epoch, output) = match update.update {
                    Update::Failure { epoch } => {
                        tracing::info!(epoch = ?epoch, pk = ?update.pk, "DKG failure");
                        (epoch, None)
                    }
                    Update::Success { epoch, output, .. } => {
                        tracing::info!(epoch = ?epoch, pk = ?update.pk, ?output, "DKG success");

                        (epoch, Some(output))
                    }
                };
                match status.get(&update.pk) {
                    None if epoch.is_zero() => {}
                    Some(e) if e.next() == epoch => {}
                    other => return Err(anyhow!("unexpected update epoch {other:?}")),
                }
                status.insert(update.pk, epoch);

                match outputs.get(current_epoch.get() as usize) {
                    None => {
                        outputs.push(output);
                        successes += 1;
                    }
                    Some(o) => {
                        if o.as_ref() != output.as_ref() {
                            return Err(anyhow!("mismatched outputs {o:?} != {output:?}"));
                        }
                    }
                }

                let post_update = if successes >= self.target {
                    PostUpdate::Stop
                } else {
                    PostUpdate::Continue
                };
                update
                    .cb_in
                    .send(post_update)
                    .map_err(|_| anyhow!("update callback closed unexpectedly"))?;

                if status.values().filter(|x| **x >= current_epoch).count() >= self.total as usize {
                    if successes >= self.target {
                        return Ok(());
                    } else {
                        current_epoch = current_epoch.next();
                    }
                }
            }

            Err(anyhow!("plan terminated unexpectedly"))
        }

        fn run<S>(self) -> anyhow::Result<()>
        where
            S: Scheme<PublicKey = PublicKey>,
            SchemeProvider<S, PrivateKey>:
                EpochSchemeProvider<Variant = MinSig, PublicKey = PublicKey, Scheme = S>,
        {
            Runner::seeded(self.seed).start(|ctx| self.run_inner(ctx))
        }
    }

    #[test_traced("INFO")]
    fn test_000() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 1,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_traced("INFO")]
    fn test_001() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 1,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_traced("INFO")]
    fn test_002() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_traced("INFO")]
    fn test_003() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_traced("INFO")]
    fn test_004() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_traced("INFO")]
    fn test_005() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: 4,
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_1k() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online::<ThresholdScheme<MinSig>>(10, 10, 0, link.clone(), 1000);
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_1k_rotate() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online::<ThresholdScheme<MinSig>>(10, 4, 0, link.clone(), 1000);
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_reshare_failed() {
        assert_eq!(reshare_failed(1), reshare_failed(1));
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_ed() {
        assert_eq!(test_marshal::<EdScheme>(1), test_marshal::<EdScheme>(1));
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_threshold() {
        assert_eq!(
            test_marshal::<ThresholdScheme<MinSig>>(1),
            test_marshal::<ThresholdScheme<MinSig>>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_multi_epoch_ed() {
        assert_eq!(
            test_marshal_multi_epoch::<EdScheme>(1),
            test_marshal_multi_epoch::<EdScheme>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_multi_epoch_threshold() {
        assert_eq!(
            test_marshal_multi_epoch::<ThresholdScheme<MinSig>>(1),
            test_marshal_multi_epoch::<ThresholdScheme<MinSig>>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_multi_epoch_non_member_of_committee_ed() {
        assert_eq!(
            test_marshal_multi_epoch_non_member_of_committee::<EdScheme>(1),
            test_marshal_multi_epoch_non_member_of_committee::<EdScheme>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_marshal_multi_epoch_non_member_of_committee_threshold() {
        assert_eq!(
            test_marshal_multi_epoch_non_member_of_committee::<ThresholdScheme<MinSig>>(1),
            test_marshal_multi_epoch_non_member_of_committee::<ThresholdScheme<MinSig>>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_unclean_shutdown_ed() {
        assert_eq!(
            test_unclean_shutdown::<EdScheme>(1),
            test_unclean_shutdown::<EdScheme>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_unclean_shutdown_threshold() {
        assert_eq!(
            test_unclean_shutdown::<ThresholdScheme<MinSig>>(1),
            test_unclean_shutdown::<ThresholdScheme<MinSig>>(1)
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    #[test_group("slow")]
    #[test_traced("INFO")]
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
