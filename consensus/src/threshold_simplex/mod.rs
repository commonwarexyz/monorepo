//! [Simplex](crate::simplex)-like BFT agreement with an embedded VRF and succinct consensus certificates.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `threshold-simplex` provides
//! simple and fast BFT agreement with network-speed view (i.e. block time) latency and optimal finalization
//! latency in a partially synchronous setting. Unlike Simplex Consensus, however, `threshold-simplex` employs threshold
//! cryptography (specifically BLS12-381 threshold signatures with a `2f+1` of `3f+1` quorum) to generate both
//! a bias-resistant beacon (for leader election and post-facto execution randomness) and succinct consensus certificates
//! (any certificate can be verified with just the static public key of the consensus instance) for each view
//! with zero message overhead (natively integrated).
//!
//! _If you wish to deploy Simplex Consensus but can't employ threshold signatures, see
//! [Simplex](crate::simplex)._
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Flexible Block Format
//! * Embedded VRF for Leader Election and Post-Facto Execution Randomness
//! * Succinct Consensus Certificates for Notarization, Nullification, and Finality
//!
//! # Design
//!
//! ## Architecture
//!
//! All logic is split into two components: the `Voter` and the `Resolver` (and the user of `threshold-simplex`
//! provides `Application`). The `Voter` is responsible for participating in the latest view and the
//! `Resolver` is responsible for fetching artifacts from previous views required to verify proposed
//! blocks in the latest view.
//!
//! To provide great performance, all interactions between `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` verifies a notarization.
//!
//! ```txt
//! +---------------+           +---------+            +++++++++++++++
//! |               |<----------+         +----------->+             +
//! |  Application  |           |  Voter  |            +    Peers    +
//! |               +---------->|         |<-----------+             +
//! +---------------+           +--+------+            +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
//!                            +-------+----+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Resolver  |          +    Peers    +
//!                            |            |<---------+             +
//!                            +------------+          +++++++++++++++
//! ```
//!
//! _Application is usually a single object that implements the `Automaton`, `Relay`, `Committer`,
//! and `ThresholdSupervisor` traits._
//!
//! ## Joining Consensus
//!
//! As soon as `2f+1` notarizes, nullifies, or finalizes are observed for some view `v`, the `Voter` will
//! enter `v+1`. This means that a new participant joining consensus will immediately jump ahead to the
//! latest view and begin participating in consensus (assuming it can verify blocks).
//!
//! ## Persistence
//!
//! The `Voter` caches all data required to participate in consensus to avoid any disk reads on
//! on the critical path. To enable recovery, the `Voter` writes valid messages it receives from
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [`Journal`](https://docs.rs/commonware-storage/latest/commonware_storage/journal/index.html).
//! Before sending a message, the `Journal` sync is invoked to prevent inadvertent Byzantine behavior
//! on restart (especially in the case of unclean shutdown).
//!
//! ## Protocol Description
//!
//! ### Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l = 2Δ` and advance `t_a = 3Δ`
//!     * If leader `l` has not been active in last `r` views, set `t_l` to 0.
//! * If leader `l`, broadcast `(part(v), notarize(c,v))`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `(part(v), notarize(c,v))` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is notarized at `v_parent` and we have nullifications for all views
//!   between `v` and `v_parent`, verify `c` and broadcast `(part(v), notarize(c,v))`
//!
//! Upon receiving `2f+1` `(part(v), notarize(c,v))`:
//! * Cancel `t_a`
//! * Mark `c` as notarized
//! * Broadcast `(seed(v), notarization(c,v))` (even if we have not verified `c`)
//! * If have not broadcast `(part(v), nullify(v))`, broadcast `finalize(c,v)`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `(part(v), nullify(v))`:
//! * Broadcast `(seed(v), nullification(v))`
//!     * If observe `>= f+1` `notarize(c,v)` for some `c`, request `notarization(c_parent, v_parent)` and any missing
//!       `nullification(*)` between `v_parent` and `v`. If `c_parent` is than last finalized, broadcast last finalization
//!       instead.
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `finalize(c,v)`:
//! * Mark `c` as finalized (and recursively finalize its parents)
//! * Broadcast `(seed(v), finalization(c,v))` (even if we have not verified `c`)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast `(part(v), nullify(v))`
//! * Every `t_r` after `(part(v), nullify(v))` broadcast that we are still in view `v`:
//!    * Rebroadcast `(part(v), nullify(v))` and either `(seed(v-1), notarization(v-1))` or `(seed(v-1), nullification(v-1))`
//!
//! #### Embedded VRF
//!
//! When broadcasting any `notarize(c,v)` or `nullify(v)` message, a participant must also include a `part(v)` message (a partial
//! signature over the view `v`). After `2f+1` `notarize(c,v)` or `nullify(v)` messages are collected from unique participants,
//! `seed(v)` can be recovered. Because `part(v)` is only over the view `v`, the seed derived for a given view `v` is the same regardless of
//! whether or not a block was notarized in said view `v`.
//!
//! Because the value of `seed(v)` cannot be known prior to message broadcast by any participant (including the leader) in view `v`
//! and cannot be manipulated by any participant (deterministic for any `2f+1` signers at a given view `v`), it can be used both as a beacon
//! for leader election (where `seed(v)` determines the leader for `v+1`) and a source of randomness in execution (where `seed(v)`
//! is used as a seed in `v`).
//!
//! #### Succinct Consensus Certificates
//!
//! All broadcast consensus messages (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`) contain partial signatures for a static
//! public key (derived from a group polynomial that can be recomputed during reconfiguration using [dkg](commonware_cryptography::bls12381::dkg)).
//! As soon as `2f+1` messages are collected, a threshold signature over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)`
//! can be recovered, respectively. Because the public key is static, any of these certificates can be verified by an external
//! process without following the consensus instance and/or tracking the current set of participants (as is typically required
//! to operate a lite client).
//!
//! These threshold signatures over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)` (i.e. the consensus certificates)
//! can be used to secure interoperability between different consensus instances and user interactions with an infrastructure provider
//! (where any data served can be proven to derive from some finalized block of some consensus instance with a known static public key).
//!
//! ### Deviations from Simplex Consensus
//!
//! * Fetch missing notarizations/nullifications as needed rather than assuming each proposal contains
//!   a set of all notarizations/nullifications for all historical blocks.
//! * Introduce distinct messages for `notarize` and `nullify` rather than referring to both as a `vote` for
//!   either a "block" or a "dummy block", respectively.
//! * Introduce a "leader timeout" to trigger early view transitions for unresponsive leaders.
//! * Skip "leader timeout" and "notarization timeout" if a designated leader hasn't participated in
//!   some number of views (again to trigger early view transition for an unresponsive leader).
//! * Introduce message rebroadcast to continue making progress if messages from a given view are dropped (only way
//!   to ensure messages are reliably delivered is with a heavyweight reliable broadcast protocol).

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actors;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
    }
}

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Monitor;
    use commonware_cryptography::{bls12381::dkg::ops, Ed25519, Sha256, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{self, Executor},
        Clock, Metrics, Runner, Spawner,
    };
    use commonware_storage::journal::variable::{Config as JConfig, Journal};
    use commonware_utils::{quorum, Array};
    use engine::Engine;
    use futures::{future::join_all, StreamExt};
    use governor::Quota;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{
        collections::{BTreeMap, HashMap},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;
    use types::Activity;

    /// Registers all validators using the oracle.
    async fn register_validators<P: Array>(
        oracle: &mut Oracle<P>,
        validators: &[P],
    ) -> HashMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))> {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (voter_sender, voter_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (resolver_sender, resolver_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            registrations.insert(
                validator.clone(),
                (
                    (voter_sender, voter_receiver),
                    (resolver_sender, resolver_receiver),
                ),
            );
        }
        registrations
    }

    /// Enum to describe the action to take when linking validators.
    enum Action {
        Link(Link),
        Update(Link), // Unlink and then link
        Unlink,
    }

    /// Links (or unlinks) validators using the oracle.
    ///
    /// The `action` parameter determines the action (e.g. link, unlink) to take.
    /// The `restrict_to` function can be used to restrict the linking to certain connections,
    /// otherwise all validators will be linked to all other validators.
    async fn link_validators<P: Array>(
        oracle: &mut Oracle<P>,
        validators: &[P],
        action: Action,
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

                // Do any unlinking first
                match action {
                    Action::Update(_) | Action::Unlink => {
                        oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                    }
                    _ => {}
                }

                // Do any linking after
                match action {
                    Action::Link(ref link) | Action::Update(ref link) => {
                        oracle
                            .add_link(v1.clone(), v2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }

    #[test_traced]
    fn test_all_online() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let max_exceptions = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no forks
                let mut exceptions = 0;
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        if notarizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
                        }
                        if notarizers.len() != n as usize {
                            exceptions += 1;
                        }
                    }
                }
                {
                    let notarizations = supervisor.notarizations.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure notarization matches digest from notarizes
                        let Some(notarization) = notarizations.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        let Some(digest) = notarized.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        assert_eq!(&notarization.proposal.payload, digest);
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }
                        let (digest, finalizers) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        if finalizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
                        }
                        if finalizers.len() != n as usize {
                            exceptions += 1;
                        }

                        // Ensure no nullifies for any finalizers
                        let nullifies = supervisor.nullifies.lock().unwrap();
                        let Some(nullifies) = nullifies.get(&view) else {
                            continue;
                        };
                        for (_, finalizers) in payloads.iter() {
                            for finalizer in finalizers.iter() {
                                if nullifies.contains(finalizer) {
                                    panic!("should not nullify and finalize at same view");
                                }
                            }
                        }
                    }
                }
                {
                    let finalizations = supervisor.finalizations.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure finalization matches digest from finalizes
                        let Some(finalization) = finalizations.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        let Some(digest) = finalized.get(&view) else {
                            exceptions += 1;
                            continue;
                        };
                        assert_eq!(&finalization.proposal.payload, digest);
                    }
                }

                // Ensure exceptions within allowed
                assert!(exceptions <= max_exceptions);
            }
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = ops::generate_shares(&mut rng, None, n, threshold);

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let (mut executor, mut context, _) = Executor::timed(Duration::from_secs(300));
        loop {
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let supervised = supervised.clone();
            let complete = executor.start({
                let mut context = context.clone();
                let public = public.clone();
                let shares = shares.clone();
                async move {
                    // Create simulated network
                    let (network, mut oracle) = Network::new(
                        context.with_label("network"),
                        Config {
                            max_size: 1024 * 1024,
                        },
                    );

                    // Start network
                    network.start();

                    // Register participants
                    let mut schemes = Vec::new();
                    let mut validators = Vec::new();
                    for i in 0..n {
                        let scheme = Ed25519::from_seed(i as u64);
                        let pk = scheme.public_key();
                        schemes.push(scheme);
                        validators.push(pk);
                    }
                    validators.sort();
                    schemes.sort_by_key(|s| s.public_key());
                    let mut registrations = register_validators(&mut oracle, &validators).await;

                    // Link all validators
                    let link = Link {
                        latency: 50.0,
                        jitter: 50.0,
                        success_rate: 1.0,
                    };
                    link_validators(&mut oracle, &validators, Action::Link(link), None).await;

                    // Create engines
                    let relay = Arc::new(mocks::relay::Relay::new());
                    let mut supervisors = HashMap::new();
                    let mut engine_handlers = Vec::new();
                    for (idx, scheme) in schemes.into_iter().enumerate() {
                        // Create scheme context
                        let context = context
                            .clone()
                            .with_label(&format!("validator-{}", scheme.public_key()));

                        // Configure engine
                        let validator = scheme.public_key();
                        let mut participants = BTreeMap::new();
                        participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                        let supervisor_config = mocks::supervisor::Config {
                            namespace: namespace.clone(),
                            participants,
                        };
                        let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                        supervisors.insert(validator.clone(), supervisor.clone());
                        let application_cfg = mocks::application::Config {
                            hasher: Sha256::default(),
                            relay: relay.clone(),
                            participant: validator.clone(),
                            propose_latency: (10.0, 5.0),
                            verify_latency: (10.0, 5.0),
                        };
                        let (actor, application) = mocks::application::Application::new(
                            context.with_label("application"),
                            application_cfg,
                        );
                        actor.start();
                        let cfg = JConfig {
                            partition: validator.to_string(),
                        };
                        let journal = Journal::init(context.with_label("journal"), cfg)
                            .await
                            .expect("unable to create journal");
                        let cfg = config::Config {
                            crypto: scheme,
                            automaton: application.clone(),
                            relay: application.clone(),
                            reporter: supervisor.clone(),
                            supervisor,
                            mailbox_size: 1024,
                            namespace: namespace.clone(),
                            leader_timeout: Duration::from_secs(1),
                            notarization_timeout: Duration::from_secs(2),
                            nullify_retry: Duration::from_secs(10),
                            fetch_timeout: Duration::from_secs(1),
                            activity_timeout,
                            skip_timeout,
                            max_fetch_count: 1,
                            fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                            fetch_concurrent: 1,
                            replay_concurrency: 1,
                        };
                        let engine = Engine::new(context.with_label("engine"), journal, cfg);

                        // Start engine
                        let (voter, resolver) = registrations
                            .remove(&validator)
                            .expect("validator should be registered");
                        engine_handlers.push(engine.start(voter, resolver));
                    }

                    // Store all finalizer handles
                    let mut finalizers = Vec::new();
                    for (_, supervisor) in supervisors.iter_mut() {
                        let (mut latest, mut monitor) = supervisor.subscribe().await;
                        finalizers.push(context.with_label("finalizer").spawn(
                            move |_| async move {
                                while latest < required_containers {
                                    latest = monitor.next().await.expect("event missing");
                                }
                            },
                        ));
                    }

                    // Exit at random points for unclean shutdown of entire set
                    let wait =
                        context.gen_range(Duration::from_millis(10)..Duration::from_millis(2_000));
                    select! {
                        _ = context.sleep(wait) => {
                            // Collect supervisors to check faults
                            {
                                let mut shutdowns = shutdowns.lock().unwrap();
                                debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                                *shutdowns += 1;
                            }
                            supervised.lock().unwrap().push(supervisors);
                            false
                        },
                        _ = join_all(finalizers) => {
                            // Check supervisors for faults activity
                            let supervised = supervised.lock().unwrap();
                            for supervisors in supervised.iter() {
                                for (_, supervisor) in supervisors.iter() {
                                    let faults = supervisor.faults.lock().unwrap();
                                    assert!(faults.is_empty());
                                }
                            }
                            true
                        }
                    }
                }
            });

            // If we are done, break
            if complete {
                break;
            }

            // Recover context
            (executor, context, _) = context.recover();
        }
    }

    #[test_traced]
    fn test_backfill() {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1, // force many fetches
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Degrade network connections for online peers
            let link = Link {
                latency: 3_000.0,
                jitter: 0.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Update(link.clone()),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Wait for nullifications to accrue
            context.sleep(Duration::from_secs(120)).await;

            // Unlink second peer from all (except first)
            link_validators(
                &mut oracle,
                &validators,
                Action::Unlink,
                Some(|_, i, j| [i, j].contains(&1usize) && ![i, j].contains(&0usize)),
            )
            .await;

            // Configure engine for first peer
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let context = context.with_label(&format!("validator-{}", validator));

            // Link first peer to all (except second)
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
            )
            .await;

            // Restore network connections for all online peers
            let link = Link {
                latency: 10.0,
                jitter: 2.5,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Update(link),
                Some(|_, i, j| ![i, j].contains(&1usize)),
            )
            .await;

            // Configure engine
            let mut participants = BTreeMap::new();
            participants.insert(0, (public.clone(), validators.clone(), shares[0]));
            let supervisor_config = mocks::supervisor::Config {
                namespace: namespace.clone(),
                participants,
            };
            let mut supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
            supervisors.push(supervisor.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let cfg = JConfig {
                partition: validator.to_string(),
            };
            let journal = Journal::init(context.with_label("journal"), cfg)
                .await
                .expect("unable to create journal");
            let cfg = config::Config {
                crypto: scheme,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                supervisor: supervisor.clone(),
                mailbox_size: 1024,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                max_fetch_count: 1,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                fetch_concurrent: 1,
                replay_concurrency: 1,
            };
            let engine = Engine::new(context.with_label("engine"), journal, cfg);

            // Start engine
            let (voter, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            engine_handlers.push(engine.start(voter, resolver));

            // Wait for new engine to finalize required
            let (mut latest, mut monitor) = supervisor.subscribe().await;
            while latest < required_containers {
                latest = monitor.next().await.expect("event missing");
            }
        });
    }

    #[test_traced]
    fn test_one_offline() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let offline = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure offline node is never active
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(offline) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
                {
                    let nullifies = supervisor.nullifies.lock().unwrap();
                    for (view, participants) in nullifies.iter() {
                        if participants.contains(offline) {
                            panic!("view: {}", view);
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(offline) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }

                // Identify offline views
                let mut offline_views = Vec::new();
                {
                    let leaders = supervisor.leaders.lock().unwrap();
                    for (view, leader) in leaders.iter() {
                        if leader == offline {
                            offline_views.push(*view);
                        }
                    }
                }
                assert!(!offline_views.is_empty());

                // Ensure nullifies/nullification collected for offline node
                {
                    let nullifies = supervisor.nullifies.lock().unwrap();
                    for view in offline_views.iter() {
                        let nullifies = nullifies.get(view).unwrap();
                        if nullifies.len() < threshold as usize {
                            panic!("view: {}", view);
                        }
                    }
                }
                {
                    let nullifications = supervisor.nullifications.lock().unwrap();
                    for view in offline_views.iter() {
                        nullifications.get(view).unwrap();
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_slow_validator() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (3_000.0, 0.0),
                        verify_latency: (3_000.0, 5.0),
                    }
                } else {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let slow = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure slow node is never active (will never process anything fast enough to nullify)
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(slow) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
                {
                    let nullifies = supervisor.nullifies.lock().unwrap();
                    for (view, participants) in nullifies.iter() {
                        // Start checking once all are online (leader may never have proposed)
                        if *view > 10 && participants.contains(slow) {
                            panic!("view: {}", view);
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(slow) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(120));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 3_000.0,
                jitter: 0.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (_, mut monitor) = supervisor.subscribe().await;
                finalizers.push(
                    context
                        .with_label("finalizer")
                        .spawn(move |context| async move {
                            select! {
                                _timeout = context.sleep(Duration::from_secs(60)) => {},
                                _done = monitor.next() => {
                                    panic!("engine should not notarize or finalize anything");
                                }
                            }
                        }),
                );
            }
            join_all(finalizers).await;

            // Update links
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Update(link), None).await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
    }

    #[test_traced]
    fn test_partition() {
        // Create context
        let n = 10;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(900));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link.clone()), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Cut all links between validator halves
            fn separated(n: usize, a: usize, b: usize) -> bool {
                let m = n / 2;
                (a < m && b >= m) || (a >= m && b < m)
            }
            link_validators(&mut oracle, &validators, Action::Unlink, Some(separated)).await;

            // Wait for any in-progress notarizations/finalizations to finish
            context.sleep(Duration::from_secs(10)).await;

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (_, mut monitor) = supervisor.subscribe().await;
                finalizers.push(
                    context
                        .with_label("finalizer")
                        .spawn(move |context| async move {
                            select! {
                                _timeout = context.sleep(Duration::from_secs(60)) => {},
                                _done = monitor.next() => {
                                    panic!("engine should not notarize or finalize anything");
                                }
                            }
                        }),
                );
            }
            join_all(finalizers).await;

            // Restore links
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(separated),
            )
            .await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                let required = latest + required_containers;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
    }

    fn slow_and_lossy_links(seed: u64) -> String {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config {
            seed,
            timeout: Some(Duration::from_secs(5_000)),
            ..deterministic::Config::default()
        };
        let (executor, mut context, auditor) = Executor::init(cfg);
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let degraded_link = Link {
                latency: 200.0,
                jitter: 150.0,
                success_rate: 0.5,
            };
            link_validators(&mut oracle, &validators, Action::Link(degraded_link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(context.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(context.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
        auditor.state()
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links(0);
    }

    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            // Run test with seed
            let state_1 = slow_and_lossy_links(seed);

            // Run test again with same seed
            let state_2 = slow_and_lossy_links(seed);

            // Ensure states are equal
            assert_eq!(state_1, state_2);
        }
    }

    #[test_traced]
    fn test_conflicter() {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::conflicter::Conflicter<_, Sha256, _> =
                        mocks::conflicter::Conflicter::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(voter);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(context.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(context.with_label("engine"), journal, cfg);
                    engine.start(voter, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_conflicting_notarize = 0;
            let mut count_conflicting_finalize = 0;
            for supervisor in supervisors.iter() {
                // Ensure only faults for byz
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::ConflictingNotarize(_) => {
                                    count_conflicting_notarize += 1;
                                }
                                Activity::ConflictingFinalize(_) => {
                                    count_conflicting_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }
            }
            assert!(count_conflicting_notarize > 0);
            assert!(count_conflicting_finalize > 0);
        });
    }

    #[test_traced]
    fn test_nuller() {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, Sha256, _> =
                        mocks::nuller::Nuller::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(voter);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(context.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(context.with_label("engine"), journal, cfg);
                    engine.start(voter, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_nullify_and_finalize = 0;
            for supervisor in supervisors.iter() {
                // Ensure only faults for byz
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::NullifyFinalize(_) => {
                                    count_nullify_and_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }
            }
            assert!(count_nullify_and_finalize > 0);
        });
    }

    #[test_traced]
    fn test_outdated() {
        // Create context
        let n = 4;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let (executor, mut context, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::outdated::Config {
                        supervisor,
                        namespace: namespace.clone(),
                        view_delta: activity_timeout * 4,
                    };
                    let engine: mocks::outdated::Outdated<_, Sha256, _> =
                        mocks::outdated::Outdated::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(voter);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(context.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(context.with_label("engine"), journal, cfg);
                    engine.start(voter, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Ensure no faults
            for supervisor in supervisors.iter() {
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
    }
}
