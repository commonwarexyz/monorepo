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

const VOTE_CHANNEL: u64 = 0;
const CERTIFICATE_CHANNEL: u64 = 1;
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
    callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
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

    let vote_limit = Quota::per_second(NZU32!(128));
    let votes = network.register(VOTE_CHANNEL, vote_limit, MESSAGE_BACKLOG);

    let certificate_limit = Quota::per_second(NZU32!(128));
    let certificates = network.register(CERTIFICATE_CHANNEL, certificate_limit, MESSAGE_BACKLOG);

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
            partition_prefix: "engine".to_string(),
            freezer_table_initial_size: 1024 * 1024, // 100mb
            peer_config,
        },
    )
    .await;

    let p2p_handle = network.start();
    let engine_handle = engine.start(
        votes,
        certificates,
        resolver,
        broadcaster,
        dkg,
        orchestrator,
        marshal,
        callback,
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
        Signer,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        utils::mux,
        Message, Receiver,
    };
    use commonware_runtime::{
        deterministic::{self, Runner},
        Clock, Handle, Runner as _, Spawner,
    };
    use commonware_utils::{union, TryCollect};
    use futures::{
        channel::{mpsc, oneshot},
        SinkExt, StreamExt,
    };
    use governor::Quota;
    use rand::seq::SliceRandom;
    use rand_core::CryptoRngCore;
    use std::{
        collections::{BTreeMap, HashSet},
        future::Future,
        num::NonZeroU32,
        pin::Pin,
        time::Duration,
    };
    use tracing::{debug, error, info};

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    #[derive(Debug)]
    struct FilteredReceiver<R> {
        inner: R,
        failures: HashSet<u64>,
    }

    impl<R: Receiver> Receiver for FilteredReceiver<R> {
        type Error = R::Error;
        type PublicKey = R::PublicKey;

        async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
            loop {
                let (pk, bytes) = self.inner.recv().await?;
                let (epoch, _) = mux::parse(bytes.clone()).expect("failed to parse mux message");
                if self.failures.contains(&epoch) {
                    debug!(?epoch, "filtered receiver dropping message");
                    continue;
                }
                return Ok((pk, bytes));
            }
        }
    }

    struct TeamUpdate {
        pk: PublicKey,
        update: Update<MinSig, PublicKey>,
        callback: oneshot::Sender<PostUpdate>,
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
                let (callback_sender, callback_receiver) = oneshot::channel();
                if sender
                    .send(TeamUpdate {
                        pk,
                        update,
                        callback: callback_sender,
                    })
                    .await
                    .is_err()
                {
                    return PostUpdate::Stop;
                };
                callback_receiver.await.unwrap_or(PostUpdate::Stop)
            })
        }
    }

    struct Team {
        peer_config: PeerConfig,
        output: Option<Output<MinSig, PublicKey>>,
        participants: BTreeMap<PublicKey, (PrivateKey, Option<Share>)>,
        handles: BTreeMap<PublicKey, Handle<()>>,
        failures: HashSet<u64>,
    }

    impl Team {
        fn reshare(mut rng: impl CryptoRngCore, total: u32, per_round: &[u32]) -> Self {
            let mut participants = (0..total)
                .map(|i| {
                    let sk = PrivateKey::from_seed(i as u64);
                    (sk.public_key(), (sk, None::<Share>))
                })
                .collect::<BTreeMap<_, _>>();
            let peer_config = PeerConfig {
                num_participants_per_round: per_round.to_vec(),
                participants: participants.keys().cloned().try_collect().unwrap(),
            };
            let (output, shares) = deal(&mut rng, Default::default(), peer_config.dealers(0))
                .expect("deal should succeed");
            for (key, share) in shares.into_iter() {
                if let Some((_, maybe_share)) = participants.get_mut(&key) {
                    *maybe_share = Some(share);
                };
            }
            Self {
                peer_config,
                output: Some(output),
                participants,
                handles: Default::default(),
                failures: HashSet::new(),
            }
        }

        fn dkg(total: u32, per_round: &[u32]) -> Self {
            let participants = (0..total)
                .map(|i| {
                    let sk = PrivateKey::from_seed(i as u64);
                    (sk.public_key(), (sk, None::<Share>))
                })
                .collect::<BTreeMap<_, _>>();
            let peer_config = PeerConfig {
                num_participants_per_round: per_round.to_vec(),
                participants: participants.keys().cloned().try_collect().unwrap(),
            };
            Self {
                peer_config,
                output: None,
                participants,
                handles: Default::default(),
                failures: HashSet::new(),
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
            let votes = control.register(VOTE_CHANNEL, TEST_QUOTA).await.unwrap();
            let certificates = control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();
            let resolver = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();
            let broadcast = control
                .register(BROADCASTER_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();
            let marshal = control.register(MARSHAL_CHANNEL, TEST_QUOTA).await.unwrap();
            let (dkg_sender, dkg_receiver) =
                control.register(DKG_CHANNEL, TEST_QUOTA).await.unwrap();
            let dkg = (
                dkg_sender,
                FilteredReceiver {
                    inner: dkg_receiver,
                    failures: self.failures.clone(),
                },
            );
            let orchestrator = control
                .register(ORCHESTRATOR_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();

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
                    output: self.output.clone(),
                    share: share.clone(),
                    partition_prefix: format!("validator_{}", &pk),
                    freezer_table_initial_size: 1024, // 1mb
                    peer_config: self.peer_config.clone(),
                },
            )
            .await;

            let handle = engine.start(
                votes,
                certificates,
                resolver,
                broadcast,
                dkg,
                orchestrator,
                marshal,
                UpdateHandler::boxed(pk.clone(), updates.clone()),
            );
            self.handles.insert(pk, handle);
        }

        async fn start(
            &mut self,
            ctx: &deterministic::Context,
            oracle: &mut Oracle<PublicKey>,
            link: Link,
            updates: mpsc::Sender<TeamUpdate>,
        ) {
            // Add links between all participants
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

            // Start all participants (even if not active at first)
            for pk in self.participants.keys().cloned().collect::<Vec<_>>() {
                if self.output.is_none() {
                    self.start_one::<EdScheme>(ctx, oracle, updates.clone(), pk.clone())
                        .await;
                } else {
                    self.start_one::<ThresholdScheme<MinSig>>(
                        ctx,
                        oracle,
                        updates.clone(),
                        pk.clone(),
                    )
                    .await;
                }
            }
        }
    }

    /// Configuration for simulating participant crashes during a test.
    #[derive(Clone)]
    struct Crash {
        /// How often to trigger crashes.
        frequency: Duration,
        /// How long crashed participants stay offline before restarting.
        downtime: Duration,
        /// Number of participants to crash each time.
        count: usize,
    }

    #[derive(Clone)]
    enum Mode {
        /// DKG mode: No initial output, uses EdScheme. Runs a single DKG.
        Dkg,
        /// Reshare mode: Starts with trusted dealer output, uses ThresholdScheme.
        /// The value specifies how many successful reshares to complete.
        Reshare(u64),
    }

    /// Test plan configuration for running DKG/reshare simulations.
    #[derive(Clone)]
    struct Plan {
        /// Random seed for deterministic execution.
        seed: u64,
        /// Total number of participants in the network.
        total: u32,
        /// Number of participants per round (cycles through the list).
        per_round: Vec<u32>,
        /// Network link configuration (latency, jitter, packet loss).
        link: Link,
        /// Whether to run in DKG or reshare mode.
        mode: Mode,
        /// Optional crash simulation configuration.
        crash: Option<Crash>,
        /// Epochs where DKG should be forced to fail by dropping all DKG messages.
        failures: HashSet<u64>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PlanResult {
        state: String,
        failures: u64,
    }

    impl Plan {
        async fn run_inner(self, mut ctx: deterministic::Context) -> anyhow::Result<PlanResult> {
            let (is_dkg, target) = match self.mode {
                Mode::Dkg => (true, 1),
                Mode::Reshare(target) => (false, target),
            };
            info!(participants = self.total, is_dkg, target, "starting test");
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
            network.start();

            let mut team = if is_dkg {
                Team::dkg(self.total, &self.per_round)
            } else {
                Team::reshare(&mut ctx, self.total, &self.per_round)
            };
            team.failures = self.failures.clone();

            let (updates_in, mut updates_out) = mpsc::channel(0);
            let (restart_sender, mut restart_receiver) = mpsc::channel::<PublicKey>(10);
            team.start(&ctx, &mut oracle, self.link.clone(), updates_in.clone())
                .await;

            // Set up crash ticker if needed
            let mut outputs = Vec::<Option<Output<MinSig, PublicKey>>>::new();
            let mut status = BTreeMap::<PublicKey, Epoch>::new();
            let mut current_epoch = Epoch::zero();
            let mut successes = 0u64;
            let mut failures = 0u64;
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
                                failures += 1;
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
                        if successes >= target {
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
                            .callback
                            .send(post_update)
                            .is_err() {
                                error!("update callback closed unexpectedly");
                                continue;
                        }

                        if status.values().filter(|x| **x >= epoch).count() >= self.total as usize {
                            if successes >= target {
                                return Ok(PlanResult {
                                    state: ctx.auditor().state(),
                                    failures,
                                });
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
                        if team.output.is_none() {
                            team.start_one::<EdScheme>(&ctx, &mut oracle, updates_in.clone(), pk).await;
                        } else {
                            team.start_one::<ThresholdScheme<MinSig>>(&ctx, &mut oracle, updates_in.clone(), pk).await;
                        }
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

        fn run(self) -> anyhow::Result<PlanResult> {
            // Multiply by total to ensure all participants report each failed epoch
            let expected_failures = self.failures.len() as u64 * self.total as u64;
            let result = Runner::seeded(self.seed).start(|ctx| self.run_inner(ctx))?;
            info!(
                failures = result.failures,
                expected_failures, "test completed"
            );
            if result.failures != expected_failures {
                return Err(anyhow!(
                    "expected {} failures, got {}",
                    expected_failures,
                    result.failures
                ));
            }
            Ok(result)
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_deterministic() {
        let plan = Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::new(),
        };
        for seed in 0..3 {
            let res0 = Plan {
                seed,
                ..plan.clone()
            }
            .run()
            .unwrap();
            let res1 = Plan {
                seed,
                ..plan.clone()
            }
            .run()
            .unwrap();
            assert_eq!(res0, res1);
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_deterministic() {
        let plan = Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(2),
            crash: None,
            failures: HashSet::new(),
        };
        for seed in 0..3 {
            let res0 = Plan {
                seed,
                ..plan.clone()
            }
            .run()
            .unwrap();
            let res1 = Plan {
                seed,
                ..plan.clone()
            }
            .run()
            .unwrap();
            assert_eq!(res0, res1);
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_single_epoch() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_single_epoch() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(1),
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_four_epochs() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(4),
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs_changing_size() {
        Plan {
            seed: 0,
            total: 8,
            per_round: vec![3, 4, 5],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(4),
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_four_epochs_lossy() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.7,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs_lossy() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.7,
            },
            mode: Mode::Reshare(4),
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs_rotating_subset() {
        Plan {
            seed: 0,
            total: 8,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(4),
            crash: None,
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_four_epochs_with_crashes() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: Some(Crash {
                frequency: Duration::from_secs(4),
                downtime: Duration::from_secs(1),
                count: 1,
            }),
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs_with_crashes() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(4),
            crash: Some(Crash {
                frequency: Duration::from_secs(4),
                downtime: Duration::from_secs(1),
                count: 1,
            }),
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_four_epochs_with_many_crashes() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: Some(Crash {
                frequency: Duration::from_secs(2),
                downtime: Duration::from_millis(500),
                count: 3,
            }),
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_four_epochs_with_many_crashes() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(4),
            crash: Some(Crash {
                frequency: Duration::from_secs(2),
                downtime: Duration::from_millis(500),
                count: 3,
            }),
            failures: HashSet::new(),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_with_forced_failure() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(1),
            crash: None,
            failures: HashSet::from([0]),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn reshare_with_many_forced_failures() {
        Plan {
            seed: 0,
            total: 8,
            per_round: vec![4, 5],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Reshare(3),
            crash: None,
            failures: HashSet::from([0, 2, 3]),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_with_forced_failure() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::from([0]),
        }
        .run()
        .unwrap();
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn dkg_with_many_forced_failures() {
        Plan {
            seed: 0,
            total: 4,
            per_round: vec![4],
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            mode: Mode::Dkg,
            crash: None,
            failures: HashSet::from([0, 1]),
        }
        .run()
        .unwrap();
    }
}
