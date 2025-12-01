//! Validator node service entrypoint.

use crate::{
    application::{EpochSchemeProvider, SchemeProvider},
    dkg::UpdateCallBack,
    engine, namespace,
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

    let max_participants_per_round = peer_config.max_participants_per_round();
    let output = config.output(max_participants_per_round);

    info!(
        public_key = %config.signing_key.public_key(),
        share = ?config.share,
        ?output,
        "Loaded participant configuration"
    );

    let p2p_namespace = union_unique(namespace::APPLICATION, b"_P2P");
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
            namespace: union(namespace::APPLICATION, b"_ENGINE"),
            output,
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
            dkg::{deal, Output},
            primitives::{group::Share, variant::MinSig},
        },
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt, Signer,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        Manager as _,
    };
    use commonware_runtime::{
        deterministic::{self, Runner},
        Clock, Handle, Runner as _, Spawner,
    };
    use commonware_utils::{ordered::Set, union};
    use futures::{
        channel::{mpsc, oneshot},
        SinkExt, StreamExt,
    };
    use governor::Quota;
    use rand::seq::SliceRandom;
    use rand_core::CryptoRngCore;
    use std::{collections::BTreeMap, future::Future, pin::Pin, time::Duration};
    use tracing::{debug, error, info};

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
                if sender.send(TeamUpdate { pk, update, cb_in }).await.is_err() {
                    return PostUpdate::Stop;
                };
                cb_out.await.unwrap_or(PostUpdate::Stop)
            })
        }
    }

    struct Team {
        peer_config: PeerConfig,
        output: Output<MinSig, PublicKey>,
        participants: BTreeMap<PublicKey, (PrivateKey, Option<Share>)>,
        handles: BTreeMap<PublicKey, Handle<()>>,
    }

    impl Team {
        fn reckon(mut rng: impl CryptoRngCore, total: u32, per_round: &[u32]) -> Self {
            let mut participants = (0..total)
                .map(|i| {
                    let sk = PrivateKey::from_seed(i as u64);
                    (sk.public_key(), (sk, None::<Share>))
                })
                .collect::<BTreeMap<_, _>>();
            let peer_config = PeerConfig {
                num_participants_per_round: per_round.to_vec(),
                participants: Set::from_iter_dedup(participants.keys().cloned()),
            };
            let (output, shares) =
                deal(&mut rng, peer_config.dealers(0)).expect("deal should succeed");
            for (key, share) in shares.into_iter() {
                if let Some((_, maybe_share)) = participants.get_mut(&key) {
                    *maybe_share = Some(share);
                };
            }
            Self {
                peer_config,
                output,
                participants,
                handles: Default::default(),
            }
        }

        async fn start_one<S>(
            &mut self,
            ctx: &deterministic::Context,
            oracle: &mut Oracle<PublicKey>,
            updates: mpsc::Sender<TeamUpdate>,
            pk: PublicKey,
        ) where
            S: Scheme<PublicKey = PublicKey>,
            SchemeProvider<S, PrivateKey>:
                EpochSchemeProvider<Variant = MinSig, PublicKey = PublicKey, Scheme = S>,
        {
            if let Some(handle) = self.handles.remove(&pk) {
                handle.abort();
            }
            let Some((sk, share)) = self.participants.get(&pk) else {
                return;
            };

            let mut control = oracle.control(pk.clone());
            let pending = control.register(PENDING_CHANNEL).await.unwrap();
            let recovered = control.register(RECOVERED_CHANNEL).await.unwrap();
            let resolver = control.register(RESOLVER_CHANNEL).await.unwrap();
            let broadcast = control.register(BROADCASTER_CHANNEL).await.unwrap();
            let marshal = control.register(MARSHAL_CHANNEL).await.unwrap();
            let dkg = control.register(DKG_CHANNEL).await.unwrap();
            let orchestrator = control.register(ORCHESTRATOR_CHANNEL).await.unwrap();

            let resolver_cfg = marshal_resolver::Config {
                public_key: pk.clone(),
                manager: oracle.manager(),
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
            let marshal = marshal_resolver::init(ctx, resolver_cfg, marshal);
            let engine = engine::Engine::<_, _, _, _, Sha256, MinSig, S>::new(
                ctx.with_label(&format!("validator_{}", &pk)),
                engine::Config {
                    signer: sk.clone(),
                    manager: oracle.manager(),
                    blocker: oracle.control(pk.clone()),
                    namespace: union(namespace::APPLICATION, b"_ENGINE"),
                    output: Some(self.output.clone()),
                    share: share.clone(),
                    orchestrator_rate_limit: Quota::per_second(NZU32!(1)),
                    partition_prefix: format!("validator_{}", &pk),
                    freezer_table_initial_size: 1024, // 1mb
                    peer_config: self.peer_config.clone(),
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
                UpdateHandler::boxed(pk.clone(), updates.clone()),
            );
            self.handles.insert(pk, handle);
        }

        async fn start<S>(
            &mut self,
            ctx: &deterministic::Context,
            oracle: &mut Oracle<PublicKey>,
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
                .update(0, Set::from_iter_dedup(self.participants.keys().cloned()))
                .await;

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

            for pk in self.participants.keys().cloned().collect::<Vec<_>>() {
                self.start_one(ctx, oracle, updates.clone(), pk.clone())
                    .await;
            }
        }
    }

    struct Crash {
        frequency: Duration,
        downtime: Duration,
        count: usize,
    }

    struct Plan {
        seed: u64,
        total: u32,
        per_round: Vec<u32>,
        link: Link,
        target: u64,
        crash: Option<Crash>,
    }

    impl Plan {
        async fn run_inner<S>(self, mut ctx: deterministic::Context) -> anyhow::Result<()>
        where
            S: Scheme<PublicKey = PublicKey>,
            SchemeProvider<S, PrivateKey>:
                EpochSchemeProvider<Variant = MinSig, PublicKey = PublicKey, Scheme = S>,
        {
            info!("starting test with {} participants", self.total);
            // Create simulated network
            let (network, mut oracle) = Network::<_, PublicKey>::new(
                ctx.with_label("network"),
                simulated::Config {
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                    max_size: 1024 * 1024,
                },
            );

            // Start network first to ensure a background task is running
            debug!("starting network actor");
            network.start();

            debug!("creating team with {} participants", self.total);
            let mut team = Team::reckon(&mut ctx, self.total, &self.per_round);

            let (updates_in, mut updates_out) = mpsc::channel(0);
            let (restart_sender, mut restart_receiver) = mpsc::channel::<PublicKey>(10);

            debug!("starting team actors and connecting");
            team.start::<S>(&ctx, &mut oracle, self.link.clone(), updates_in.clone())
                .await;

            debug!("waiting for updates");
            let mut outputs = Vec::<Option<Output<MinSig, PublicKey>>>::new();
            let mut status = BTreeMap::<PublicKey, Epoch>::new();
            let mut current_epoch = Epoch::zero();
            let mut successes = 0u64;

            // Set up crash ticker if needed
            let (crash_sender, mut crash_receiver) = mpsc::channel::<()>(1);
            if let Some(crash) = &self.crash {
                let frequency = crash.frequency;
                let mut crash_sender = crash_sender.clone();
                ctx.clone().spawn(move |ctx| async move {
                    loop {
                        ctx.sleep(frequency).await;
                        if crash_sender.send(()).await.is_err() {
                            break;
                        }
                    }
                });
            }

            let mut success_target_reached_epoch = None;

            loop {
                select! {
                    update = updates_out.next() => {
                        let Some(update) = update else {
                            return Err(anyhow!("update channel closed unexpectedly"));
                        };
                        let (epoch, output) = match update.update {
                            Update::Failure { epoch } => {
                                info!(epoch = ?epoch, pk = ?update.pk, "DKG failure");
                                (epoch, None)
                            }
                            Update::Success { epoch, output, .. } => {
                                info!(epoch = ?epoch, pk = ?update.pk, ?output, "DKG success");

                                (epoch, Some(output))
                            }
                        };
                        match status.get(&update.pk) {
                            None if epoch.is_zero() => {}
                            Some(e) if e.next() == epoch => {}
                            other => return Err(anyhow!("unexpected update epoch {other:?}")),
                        }
                        status.insert(update.pk, epoch);

                        match outputs.get(epoch.get() as usize) {
                            None => {
                                if output.is_some() {
                                    successes += 1;
                                }
                                outputs.push(output);
                            }
                            Some(o) => {
                                if o.as_ref() != output.as_ref() {
                                    return Err(anyhow!("mismatched outputs {o:?} != {output:?}"));
                                }
                            }
                        }
                        if successes >= self.target {
                            success_target_reached_epoch = Some(epoch);
                        }
                        let all_reached_epoch = status.values().filter(|e| matches!(success_target_reached_epoch, Some(target) if **e >= target)
                        ).count() >= self.total as usize;

                        let post_update = if all_reached_epoch {
                            PostUpdate::Stop
                        } else {
                            PostUpdate::Continue
                        };
                        if update
                            .cb_in
                            .send(post_update)
                            .is_err() {
                                error!("update callback closed unexpectedly");
                                continue;
                        }

                        if status.values().filter(|x| **x >= epoch).count() >= self.total as usize {
                            if successes >= self.target {
                                return Ok(());
                            } else {
                                current_epoch = current_epoch.next();
                            }
                        }
                    },
                    pk = restart_receiver.next() => {
                        let Some(pk) = pk else {
                            continue;
                        };

                        info!(pk = ?pk, "restarting participant");
                        team.start_one::<S>(&ctx, &mut oracle, updates_in.clone(), pk).await;
                    },
                    _ = crash_receiver.next() => {
                        // Crash ticker fired
                        if let Some(crash) = &self.crash {
                            // Pick multiple random participants to crash
                            let all_participants: Vec<PublicKey> = team.participants.keys().cloned().collect();
                            let crash_count = crash.count.min(all_participants.len());
                            let to_crash: Vec<PublicKey> = all_participants.choose_multiple(&mut ctx, crash_count).cloned().collect();

                            for pk in to_crash {
                                // Try to abort the handle if it exists
                                if let Some(handle) = team.handles.remove(&pk) {
                                    handle.abort();
                                    info!(pk = ?pk, "crashed participant");

                                    // Schedule restart after downtime
                                    let mut restart_sender = restart_sender.clone();
                                    let downtime = crash.downtime;
                                    let pk_clone = pk.clone();
                                    ctx.clone().spawn(move |ctx| async move {
                                        if downtime > Duration::ZERO {
                                            ctx.sleep(downtime).await;
                                        }
                                        let _ = restart_sender.send(pk_clone).await;
                                    });
                                } else {
                                    debug!(pk = ?pk, "participant already crashed");
                                }
                            }
                        }
                    },
                }
            }
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

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn single_epoch_ed_scheme_success() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 1,
            crash: None,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn single_epoch_threshold_scheme_success() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 1,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_scheme_all_participants() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_scheme_all_participants() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_scheme_changing_size() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: vec![3, 4, 5],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_scheme_changing_size() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: vec![3, 4, 5],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_all_participants_lossy() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 0.7,
            },
            target: 4,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_scheme_all_participants_lossy() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 0.7,
            },
            target: 4,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_scheme_rotating_subset() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_scheme_rotating_subset() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 8,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: None,
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_with_crashes_and_recovery() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: Some(Crash {
                frequency: Duration::from_secs(4),
                downtime: Duration::from_secs(1),
                count: 1,
            }),
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_with_crashes_and_recovery() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: Some(Crash {
                frequency: Duration::from_secs(4),
                downtime: Duration::from_secs(2),
                count: 1,
            }),
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_ed_with_many_crashes_and_recovery() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: Some(Crash {
                frequency: Duration::from_secs(2),
                downtime: Duration::from_millis(500),
                count: 3,
            }),
        }
        .run::<EdScheme>())
        {
            panic!("failure: {e}");
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn four_epoch_threshold_with_many_crashes_and_recovery() {
        if let Err(e) = (Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            },
            target: 4,
            crash: Some(Crash {
                frequency: Duration::from_secs(2),
                downtime: Duration::from_millis(500),
                count: 3,
            }),
        }
        .run::<ThresholdScheme<MinSig>>())
        {
            panic!("failure: {e}");
        }
    }
}
