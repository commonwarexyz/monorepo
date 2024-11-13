//! Authority
//!
//! PoA Consensus useful for running a DKG (round-robin leader selection, update participants with config).
//!
//! All decisions made to minimize container time and finalization latency without sacrificing
//! the ability to attribute uptime and faults.
//!
//! # Externalizable Uptime and Faults
//!
//! Instead of handling uptime and fault tracking internally, the application is notified of all
//! activity and can incorportate such information as needed (into the payload or otherwise).
//!
//! # Sync
//!
//! Wait for container notarization at tip (2f+1), fetch heights backwards (don't
//! need to backfill views).
//!
//! # Async Handling
//!
//! All application interaction occurs asynchronously, meaning that the engine can continue processing messages
//! while a payload is being built or verified (usually take hundreds of milliseconds).
//!
//! # Dedicated Processing for Consensus Messages
//!
//! All peer interaction related to consensus is strictly prioritized over any other messages (i.e. helping new
//! peers sync to the network).
//!
//! # Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l` and advance `t_a`
//!     * If leader `l` has not been active (no votes) in last `r` views, set `t_l` to 0.
//! * If leader, propose container `c` for view `v`
//!
//! Upon receiving first container `c` from `l`:
//! * Cancel `t_l`
//! * If we have `c_parent`, have verified `c_parent`, `c_parent` is notarized (either implicitly or explicitly), and we have null notarizations
//!   for all views between `c_parent` and `c`, then broadcast vote for `c`.
//!
//! Upon receiving `2f+1` votes for `c`:
//! * Cancel `t_a`
//! * Broadcast `c` to all nodes that didn't vote for `c` (otherwise won't vote for next honest proposal -> other constructions typically don't handle this case and instead
//!   rely on some form of leader backfill in their slot or aim to fetch as soon as they realize they are missing a block but by then in this construction, their slot
//!   has already started as they'd only want to backfill after seeing `2f+1` votes for the proposal)
//! * Broadcast notarization for `c`
//! * If have not broadcast null vote for view `v`, broadcast finalize for `c`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` null votes for `v`:
//! * Broadcast null notarization for `v`
//! * Enter `v+1`
//! * If leader:
//!    * Dependent Notarizations: Send notarization for `c_parent` and `j` random null notarizations for views between `c_parent` and `c` to anyone
//!      that didn't vote for `c` (if node was offline or messages dropped, may never be able to vote without this)
//!
//! Upon receiving `2f+1` finalizes for `c`:
//! * Broadcast finalization for `c`
//! * Finalize `c` at height `h` (and recursively finalize its parents)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast null vote for view `v`
//!
//! ## Differences from Simplex
//!
//! * Distinct Leader timeout (in addition to notarization timeout)
//!     * Skip leader timeout/notarization timeout if we haven't seen a participant vote in some number of views
//! * Periodically retry building of proposal
//! * [NOT SAFE] Backfill containers from notarizing peers rather than passing along with notarization message
//! * Uptime/Fault tracking (over `n` previous heights instead of waiting for some timeout after notarization for
//!   more votes)
//! * Dynamic sync for new nodes (join consensus at tip right away and backfill history + new containers on-the-fly)/no dedicated
//!   "sync" phase
//! * Only multicast proposal `c` in `v` on transition to `v+1  to peers that haven't already voted for `c`
//! * Only multicast dependent notarizations (notarization for `c_parent` and null notarizations between `c_parent` and `c`) for `v` to peers that
//!   didn't vote for `c`
//!
//! # What is a good fit?
//!
//! * Desire fast block times (as fast as possible): No message relay through leader
//! * Proposals are small (include references to application data rather than application data itself): Each notarization may require each party to re-broadcast the proposal
//! * Small to medium number of validators (< 500): All messages are broadcast
//! * Strong robustness against Byzantine leaders? (still can trigger later than desired start to verification) but can't force a fetch
//!     * Saves at least 1 RTT (and more if first recipient doesn't have/is byzantine)
//!
//! # Performance Degradation
//!
//! * Ever-growing unfinalized tip: processing views are cached in-memory
//!     * Particularly bad if composed of null notarizations

mod actors;
pub mod byzantine;
mod config;
mod encoder;
mod engine;
pub mod mocks;
mod prover;

use commonware_cryptography::{Digest, PublicKey};
pub use config::Config;
pub use engine::Engine;
pub use prover::Prover;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

pub type View = u64;
pub type Height = u64;

/// Context is a collection of information about the context in which a container is built.
#[derive(Clone)]
pub struct Context {
    pub view: View,
    pub parent: Digest,
    pub height: Height,
    pub proposer: PublicKey,
}

use crate::Activity;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid container")]
    InvalidContainer,
    #[error("Invalid signature")]
    InvalidSignature,
}

pub const PROPOSAL: Activity = 0;
pub const VOTE: Activity = 1;
pub const FINALIZE: Activity = 2;
pub const CONFLICTING_PROPOSAL: Activity = 3;
/// Note: it is ok to have both a vote for a proposal and the null
/// container in the same view.
pub const CONFLICTING_VOTE: Activity = 4;
pub const CONFLICTING_FINALIZE: Activity = 5;
pub const NULL_AND_FINALIZE: Activity = 6;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Proof, Supervisor};
    use bytes::Bytes;
    use byzantine::{
        conflicter::{self, Conflicter},
        nuller::{self, Nuller},
    };
    use commonware_cryptography::{Ed25519, Hasher, PublicKey, Scheme, Sha256};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network};
    use commonware_runtime::{
        deterministic::{self, Executor},
        Clock, Runner, Spawner,
    };
    use engine::Engine;
    use futures::{channel::mpsc, StreamExt};
    use governor::Quota;
    use mocks::{Application, Config as ApplicationConfig, Progress};
    use prometheus_client::registry::Registry;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::{debug, info};

    type HeightActivity = HashMap<Height, HashMap<Digest, HashSet<PublicKey>>>;
    type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

    #[derive(Clone)]
    struct TestSupervisor<C: Scheme, H: Hasher> {
        participants: BTreeMap<View, (HashSet<PublicKey>, Vec<PublicKey>)>,

        prover: Prover<C, H>,

        proposals: Arc<Mutex<HeightActivity>>,
        votes: Arc<Mutex<HeightActivity>>,
        finalizes: Arc<Mutex<HeightActivity>>,
        faults: Arc<Mutex<Faults>>,
    }

    impl<C: Scheme, H: Hasher> TestSupervisor<C, H> {
        fn new(prover: Prover<C, H>, participants: BTreeMap<View, Vec<PublicKey>>) -> Self {
            let mut parsed_participants = BTreeMap::new();
            for (view, mut validators) in participants.into_iter() {
                let mut set = HashSet::new();
                for validator in validators.iter() {
                    set.insert(validator.clone());
                }
                validators.sort();
                parsed_participants.insert(view, (set.clone(), validators));
            }
            Self {
                participants: parsed_participants,
                prover,
                proposals: Arc::new(Mutex::new(HashMap::new())),
                votes: Arc::new(Mutex::new(HashMap::new())),
                finalizes: Arc::new(Mutex::new(HashMap::new())),
                faults: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl<C: Scheme, H: Hasher> Supervisor for TestSupervisor<C, H> {
        type Index = View;

        fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
            let closest = match self.participants.range(..=index).next_back() {
                Some((_, p)) => p,
                None => {
                    panic!("no participants in required range");
                }
            };
            Some(&closest.1)
        }

        fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<bool> {
            let closest = match self.participants.range(..=index).next_back() {
                Some((_, p)) => p,
                None => {
                    panic!("no participants in required range");
                }
            };
            Some(closest.0.contains(candidate))
        }

        async fn report(&mut self, activity: Activity, proof: Proof) {
            // We check signatures for all messages to ensure that the prover is working correctly
            // but in production this isn't necessary (as signatures are already verified in
            // consensus).
            match activity {
                PROPOSAL => {
                    let (public_key, _, height, digest) =
                        self.prover.deserialize_proposal(proof, true).unwrap();
                    self.proposals
                        .lock()
                        .unwrap()
                        .entry(height)
                        .or_default()
                        .entry(digest)
                        .or_default()
                        .insert(public_key);
                }
                VOTE => {
                    let (public_key, _, height, digest) =
                        self.prover.deserialize_vote(proof, true).unwrap();
                    self.votes
                        .lock()
                        .unwrap()
                        .entry(height)
                        .or_default()
                        .entry(digest)
                        .or_default()
                        .insert(public_key);
                }
                FINALIZE => {
                    let (public_key, _, height, digest) =
                        self.prover.deserialize_finalize(proof, true).unwrap();
                    self.finalizes
                        .lock()
                        .unwrap()
                        .entry(height)
                        .or_default()
                        .entry(digest)
                        .or_default()
                        .insert(public_key);
                }
                CONFLICTING_PROPOSAL => {
                    let (public_key, view) = self
                        .prover
                        .deserialize_conflicting_proposal(proof, true)
                        .unwrap();
                    self.faults
                        .lock()
                        .unwrap()
                        .entry(public_key)
                        .or_default()
                        .entry(view)
                        .or_default()
                        .insert(CONFLICTING_PROPOSAL);
                }
                CONFLICTING_VOTE => {
                    let (public_key, view) = self
                        .prover
                        .deserialize_conflicting_vote(proof, true)
                        .unwrap();
                    self.faults
                        .lock()
                        .unwrap()
                        .entry(public_key)
                        .or_default()
                        .entry(view)
                        .or_default()
                        .insert(CONFLICTING_VOTE);
                }
                CONFLICTING_FINALIZE => {
                    let (public_key, view) = self
                        .prover
                        .deserialize_conflicting_finalize(proof, true)
                        .unwrap();
                    self.faults
                        .lock()
                        .unwrap()
                        .entry(public_key)
                        .or_default()
                        .entry(view)
                        .or_default()
                        .insert(CONFLICTING_FINALIZE);
                }
                NULL_AND_FINALIZE => {
                    let (public_key, view) =
                        self.prover.deserialize_null_finalize(proof, true).unwrap();
                    self.faults
                        .lock()
                        .unwrap()
                        .entry(public_key)
                        .or_default()
                        .entry(view)
                        .or_default()
                        .insert(NULL_AND_FINALIZE);
                }
                a => {
                    panic!("unexpected activity: {}", a);
                }
            }
        }
    }

    #[test_traced]
    fn test_all_online() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme,
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, digest) = event {
                    finalized.insert(height, digest);
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Check supervisors for correct activity
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no forks
                {
                    let proposals = supervisor.proposals.lock().unwrap();
                    for (height, views) in proposals.iter() {
                        // Ensure no skips (height == view)
                        if views.len() > 1 {
                            panic!("height: {}, views: {:?}", height, views);
                        }

                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let proposers = views.get(digest).expect("digest should exist");
                        if proposers.len() != 1 {
                            panic!("height: {}, proposers: {:?}", height, proposers);
                        }
                    }
                }
                {
                    let votes = supervisor.votes.lock().unwrap();
                    for (height, views) in votes.iter() {
                        // Ensure no skips (height == view)
                        if views.len() > 1 {
                            panic!("height: {}, views: {:?}", height, views);
                        }

                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let voters = views.get(digest).expect("digest should exist");
                        if voters.len() != n {
                            panic!("height: {}, voters: {:?}", height, voters);
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        // Ensure no skips (height == view)
                        if views.len() > 1 {
                            panic!("height: {}, views: {:?}", height, views);
                        }

                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let finalizers = views.get(digest).expect("digest should exist");
                        if finalizers.len() != n {
                            panic!("height: {}, finalizers: {:?}", height, finalizers);
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_one_offline() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(60));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme,
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

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
                    let proposals = supervisor.proposals.lock().unwrap();
                    for (height, views) in proposals.iter() {
                        for (_, proposers) in views.iter() {
                            if proposers.contains(offline) {
                                panic!("height: {}, proposers: {:?}", height, proposers);
                            }
                        }
                    }
                }
                {
                    let votes = supervisor.votes.lock().unwrap();
                    for (height, views) in votes.iter() {
                        for (_, voters) in views.iter() {
                            if voters.contains(offline) {
                                panic!("height: {}, voters: {:?}", height, voters);
                            }
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        for (_, finalizers) in views.iter() {
                            if finalizers.contains(offline) {
                                panic!("height: {}, finalizers: {:?}", height, finalizers);
                            }
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_slow_validator() {
        // Create runtime
        let n = 5;
        let required_containers = 30;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(300));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = if idx == 0 {
                    ApplicationConfig {
                        hasher: hasher.clone(),
                        supervisor,
                        participant: validator,
                        sender: done_sender.clone(),
                        propose_latency: (3_000.0, 0.0),
                        parse_latency: (10.0, 5.0),
                        verify_latency: (3_000.0, 0.0),
                        allow_invalid_payload: false,
                    }
                } else {
                    ApplicationConfig {
                        hasher: hasher.clone(),
                        supervisor,
                        participant: validator,
                        sender: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        parse_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        allow_invalid_payload: false,
                    }
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme,
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, digest) = event {
                    finalized.insert(height, digest);
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Check supervisors for correct activity
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure no faults (i.e. voting for both whatever is eventually processed and timeout)
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Verify no participation from slow validator
                {
                    let proposals = supervisor.proposals.lock().unwrap();
                    for (height, views) in proposals.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure slow validator never has a proposal
                        for (_, proposers) in views.iter() {
                            if proposers.contains(&validators[0]) {
                                panic!(
                                    "slow proposer should never have participated: height={}",
                                    height
                                );
                            }
                        }
                    }
                }
                {
                    let votes = supervisor.votes.lock().unwrap();
                    for (height, views) in votes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let voters = views.get(digest).expect("digest should exist");
                        if voters.len() != n - 1 {
                            panic!("height: {}, voters: {:?}", height, voters.len());
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let finalizers = views.get(digest).expect("digest should exist");
                        if finalizers.len() != n - 1 {
                            panic!("height: {}, finalizers: {:?}", height, finalizers.len());
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_catchup() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 2.5,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 32,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height > highest_finalized {
                        highest_finalized = height;
                    }
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

            // Link to all other validators
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            for other in validators.iter() {
                if other == &validator {
                    continue;
                }
                oracle
                    .add_link(
                        validator.clone(),
                        other.clone(),
                        Link {
                            latency: 10.0,
                            jitter: 2.5,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
                oracle
                    .add_link(
                        other.clone(),
                        validator.clone(),
                        Link {
                            latency: 10.0,
                            jitter: 2.5,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            // Start engine
            let (container_sender, container_receiver) = oracle
                .register(validator.clone(), 0, 1024 * 1024)
                .await
                .unwrap();
            let (vote_sender, vote_receiver) = oracle
                .register(validator.clone(), 1, 1024 * 1024)
                .await
                .unwrap();
            let hasher = Sha256::default();
            let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                Prover::new(hasher.clone(), namespace.clone()),
                view_validators.clone(),
            );
            supervisors.push(supervisor.clone());
            let application_cfg = ApplicationConfig {
                hasher: hasher.clone(),
                supervisor,
                participant: validator.clone(),
                sender: done_sender.clone(),
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let application = Application::new(runtime.clone(), application_cfg);
            let cfg = config::Config {
                crypto: scheme,
                hasher,
                application,
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                null_vote_retry: Duration::from_secs(10),
                proposal_retry: Duration::from_millis(100),
                fetch_timeout: Duration::from_secs(2),
                activity_timeout: 10,
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                validators: view_validators.clone(),
            };
            let engine = Engine::new(runtime.clone(), cfg);
            runtime.spawn("engine", async move {
                engine
                    .run(
                        (container_sender, container_receiver),
                        (vote_sender, vote_receiver),
                    )
                    .await;
            });

            // Wait for new engine to finish
            loop {
                let (candidate, event) = done_receiver.next().await.unwrap();
                if validator != candidate {
                    continue;
                }
                if let Progress::Finalized(height, _) = event {
                    if height < highest_finalized + required_containers {
                        // We want to see `required_containers` once we catch up
                        continue;
                    }
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_catchup_recovery() {
        // Create runtime
        let n = 4;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 2.5,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 32,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height > highest_finalized {
                        highest_finalized = height;
                    }
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

            // Degrade network connections for online peers
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Degrade connection
                let validator = scheme.public_key();
                for (other_idx, other) in validators.iter().enumerate() {
                    if other_idx == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 3_000.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for some null notarizations to pile up
            runtime.sleep(Duration::from_secs(120)).await;

            // Remove all connections from first online peer (at index 1)
            let failed_validator = validators[1].clone();
            for (other_idx, other) in validators.iter().enumerate() {
                if other_idx == 0 {
                    continue;
                }
                if other == &failed_validator {
                    continue;
                }
                oracle
                    .remove_link(failed_validator.clone(), other.clone())
                    .await
                    .unwrap();
                oracle
                    .remove_link(other.clone(), failed_validator.clone())
                    .await
                    .unwrap();
            }

            // Start engine for first peer
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let (container_sender, container_receiver) = oracle
                .register(validator.clone(), 0, 1024 * 1024)
                .await
                .unwrap();
            let (vote_sender, vote_receiver) = oracle
                .register(validator.clone(), 1, 1024 * 1024)
                .await
                .unwrap();

            // Restore network connections for online peers
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip newly offline peer
                if idx == 1 {
                    continue;
                }

                // Restore connection
                let validator = scheme.public_key();
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 1 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 2.5,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Start engine
            let hasher = Sha256::default();
            let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                Prover::new(hasher.clone(), namespace.clone()),
                view_validators.clone(),
            );
            supervisors.push(supervisor.clone());
            let application_cfg = ApplicationConfig {
                hasher: hasher.clone(),
                supervisor,
                participant: validator.clone(),
                sender: done_sender.clone(),
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let application = Application::new(runtime.clone(), application_cfg);
            let cfg = config::Config {
                crypto: scheme,
                hasher,
                application,
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                null_vote_retry: Duration::from_secs(10),
                proposal_retry: Duration::from_millis(100),
                fetch_timeout: Duration::from_secs(2),
                activity_timeout: 10,
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                validators: view_validators.clone(),
            };
            let engine = Engine::new(runtime.clone(), cfg);
            runtime.spawn("engine", async move {
                engine
                    .run(
                        (container_sender, container_receiver),
                        (vote_sender, vote_receiver),
                    )
                    .await;
            });

            // Wait for new engine to finish
            loop {
                let (candidate, event) = done_receiver.next().await.unwrap();
                if validator != candidate {
                    continue;
                }
                if let Progress::Finalized(height, _) = event {
                    if height < highest_finalized + required_containers {
                        // We want to see `required_containers` once we catch up
                        continue;
                    }
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(120));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 3000.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(60)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Update links
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_no_finality() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 800.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(1),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to notarize
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                match event {
                    Progress::Notarized(height, _) => {
                        if height < required_containers {
                            continue;
                        }
                        completed.insert(validator);
                    }
                    Progress::Finalized(_, _) => {
                        panic!("should not finalize");
                    }
                }
                if completed.len() == n {
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_partition() {
        // Create runtime
        let n = 10;
        let required_containers = 25;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(900));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to finalize
            let mut completed = HashSet::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height > highest_finalized {
                        highest_finalized = height;
                    }
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Cut all links between validator halves
            for (me_idx, me) in validators.iter().enumerate() {
                for (other_idx, other) in validators.iter().enumerate() {
                    if other == me {
                        continue;
                    }
                    if me_idx < n / 2 && other_idx >= n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                    if me_idx >= n / 2 && other_idx < n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                }
            }

            // Wait for any in-progress notarizations/finalizations to finish
            runtime.sleep(Duration::from_secs(10)).await;

            // Empty done receiver
            loop {
                if done_receiver.try_next().is_err() {
                    break;
                }
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(600)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Restore links
            debug!("restoring links");
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height < required_containers + highest_finalized {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_lossy_links() {
        // Create runtime
        let n = 10;
        let required_containers = 100;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(300));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 0.7,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme,
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(5).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });
    }

    fn slow_and_lossy_links(seed: u64) -> String {
        // Create runtime
        let n = 10;
        let required_containers = 20;
        let namespace = Bytes::from("consensus");
        let cfg = deterministic::Config {
            seed,
            timeout: Some(Duration::from_secs(180)),
            ..Default::default()
        };
        let (executor, runtime, auditor) = Executor::init(cfg);
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 200.0,
                                jitter: 150.0,
                                success_rate: 0.8,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                    Prover::new(hasher.clone(), namespace.clone()),
                    view_validators.clone(),
                );
                supervisors.push(supervisor.clone());
                let application_cfg = ApplicationConfig {
                    hasher: hasher.clone(),
                    supervisor,
                    participant: validator,
                    sender: done_sender.clone(),
                    propose_latency: (50.0, 10.0),
                    parse_latency: (10.0, 5.0),
                    verify_latency: (25.0, 5.0),
                    allow_invalid_payload: false,
                };
                let application = Application::new(runtime.clone(), application_cfg);
                let cfg = config::Config {
                    crypto: scheme,
                    hasher,
                    application,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    proposal_retry: Duration::from_millis(100),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout: 10,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(5).unwrap()),
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, _) = event {
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Ensure no faults
            for supervisor in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        });

        // Return auditor state
        auditor.state()
    }

    #[test_traced]
    fn test_determinism() {
        for seed in 0..5 {
            // Run test with seed
            let state = slow_and_lossy_links(seed);

            // Run test again with same seed
            let new_state = slow_and_lossy_links(seed);

            // Ensure states are equal
            assert_eq!(state, new_state);
        }
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        // We start at 5 because `test_determinism` already tests seeds 0..5
        for seed in 5..10 {
            info!(seed, "running test with seed");
            slow_and_lossy_links(seed);
        }
    }

    #[test_traced]
    fn test_conflicter() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(60));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                if idx == 0 {
                    let cfg = conflicter::Config {
                        crypto: scheme,
                        hasher,
                        namespace: namespace.clone(),
                    };
                    let engine = Conflicter::new(runtime.clone(), cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                } else {
                    let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                        Prover::new(hasher.clone(), namespace.clone()),
                        view_validators.clone(),
                    );
                    supervisors.push(supervisor.clone());
                    let application_cfg = ApplicationConfig {
                        hasher: hasher.clone(),
                        supervisor,
                        participant: validator,
                        sender: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        parse_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        allow_invalid_payload: true,
                    };
                    let application = Application::new(runtime.clone(), application_cfg);
                    let cfg = config::Config {
                        crypto: scheme,
                        hasher,
                        application,
                        registry: Arc::new(Mutex::new(Registry::default())),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        null_vote_retry: Duration::from_secs(10),
                        proposal_retry: Duration::from_millis(100),
                        fetch_timeout: Duration::from_secs(2),
                        activity_timeout,
                        max_fetch_count: 1,
                        max_fetch_size: 1024 * 512,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        validators: view_validators.clone(),
                    };
                    let engine = Engine::new(runtime.clone(), cfg);
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                }
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, digest) = event {
                    finalized.insert(height, digest);
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

            // Check supervisors for correct activity
            let offline = &validators[0];
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure only faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(offline).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match *fault {
                                CONFLICTING_PROPOSAL => {}
                                CONFLICTING_VOTE => {}
                                CONFLICTING_FINALIZE => {}
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }

                // Ensure other nodes are active as usual
                {
                    let votes = supervisor.votes.lock().unwrap();
                    for (height, views) in votes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("missing finalized digest");
                        let count = views.get(digest).expect("missing finalized view").len();
                        if count < n - 1 {
                            panic!(
                                "incorrect votes at height: {} ({} < {})",
                                height,
                                count,
                                n - 1
                            );
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("missing finalized digest");
                        let count = views.get(digest).expect("missing finalized view").len();
                        if count < n - 1 {
                            panic!(
                                "incorrect finalizes at height: {} ({} < {})",
                                height,
                                count,
                                n - 1
                            );
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_nuller() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(60));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

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
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let hasher = Sha256::default();
                if idx == 0 {
                    let cfg = nuller::Config {
                        crypto: scheme,
                        hasher,
                        namespace: namespace.clone(),
                    };
                    let engine = Nuller::new(runtime.clone(), cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                } else {
                    let supervisor = TestSupervisor::<Ed25519, Sha256>::new(
                        Prover::new(hasher.clone(), namespace.clone()),
                        view_validators.clone(),
                    );
                    supervisors.push(supervisor.clone());
                    let application_cfg = ApplicationConfig {
                        hasher: hasher.clone(),
                        supervisor,
                        participant: validator,
                        sender: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        parse_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        allow_invalid_payload: false,
                    };
                    let application = Application::new(runtime.clone(), application_cfg);
                    let cfg = config::Config {
                        crypto: scheme,
                        hasher,
                        application,
                        registry: Arc::new(Mutex::new(Registry::default())),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        null_vote_retry: Duration::from_secs(10),
                        proposal_retry: Duration::from_millis(100),
                        fetch_timeout: Duration::from_secs(2),
                        activity_timeout,
                        max_fetch_count: 1,
                        max_fetch_size: 1024 * 512,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        validators: view_validators.clone(),
                    };
                    let engine = Engine::new(runtime.clone(), cfg);
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                }
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height, digest) = event {
                    finalized.insert(height, digest);
                    if height < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

            // Check supervisors for correct activity
            let offline = &validators[0];
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure only faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(offline).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match *fault {
                                CONFLICTING_VOTE => {}
                                NULL_AND_FINALIZE => {}
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }

                // Ensure other nodes are active as usual
                {
                    let votes = supervisor.votes.lock().unwrap();
                    for (height, views) in votes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("missing finalized digest");
                        let count = views.get(digest).expect("missing finalized view").len();
                        if count < n - 1 {
                            panic!(
                                "incorrect votes at height: {} ({} < {})",
                                height,
                                count,
                                n - 1
                            );
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("missing finalized digest");
                        let count = views.get(digest).expect("missing finalized view").len();
                        if count < n - 1 {
                            panic!(
                                "incorrect finalizes at height: {} ({} < {})",
                                height,
                                count,
                                n - 1
                            );
                        }
                    }
                }
            }
        });
    }
}
