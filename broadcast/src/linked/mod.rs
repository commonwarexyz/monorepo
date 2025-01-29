use commonware_cryptography::PublicKey;

mod encoder;

#[cfg(test)]
pub mod mocks;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

pub mod prover;
pub mod signer;

pub type Epoch = u64;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context {
    pub sequencer: PublicKey,
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::{mocks, signer};
    use bytes::Bytes;
    use commonware_cryptography::{bls12381::dkg::ops, Ed25519, Hasher, PublicKey, Scheme, Sha256};
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic::Executor, Clock, Runner, Spawner};
    use commonware_storage::journal::{self, Journal};
    use commonware_utils::hex;
    use futures::channel::oneshot;
    use prometheus_client::registry::Registry;
    use tracing::debug;

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle,
        validators: &[PublicKey],
    ) -> HashMap<PublicKey, ((Sender, Receiver), (Sender, Receiver))> {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (a1, a2) = oracle.register(validator.clone(), 0).await.unwrap();
            let (b1, b2) = oracle.register(validator.clone(), 1).await.unwrap();
            registrations.insert(validator.clone(), ((a1, a2), (b1, b2)));
        }
        registrations
    }

    /// Enum to describe the action to take when linking validators.
    #[allow(dead_code)] // TODO: remove when used
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
    async fn link_validators(
        oracle: &mut Oracle,
        validators: &[PublicKey],
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
    fn test_signer() {
        let num_validators = 4;
        let quorum = 3;
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut runtime, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        executor.start({
            let runtime = runtime.clone();
            async move {
                // Create network
                let (network, mut oracle) = Network::new(
                    runtime.clone(),
                    commonware_p2p::simulated::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        max_size: 1024 * 1024,
                    },
                );
                runtime.spawn("network", network.run());

                // Create validators
                let mut validators = (0..num_validators)
                    .map(|i| Ed25519::from_seed(i as u64))
                    .collect::<Vec<_>>();
                validators.sort_by_key(|s| s.public_key());
                let validators = validators
                    .iter()
                    .enumerate()
                    .map(|(i, scheme)| {
                        let pk = scheme.public_key();
                        let share = shares_vec[i];
                        (pk, scheme.clone(), share)
                    })
                    .collect::<Vec<_>>();
                let pks = validators
                    .iter()
                    .map(|(pk, _, _)| pk.clone())
                    .collect::<Vec<_>>();
                let mut registrations = register_validators(&mut oracle, &pks).await;
                let link = Link {
                    latency: 10.0,
                    jitter: 1.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &pks, Action::Link(link), None).await;

                // Create collections
                let (collector, collector_mailbox) = mocks::collector::Collector::new();
                runtime.spawn("collector", collector.run());

                // Create engines
                let mut mailboxes = HashMap::new();
                for (validator, scheme, share) in validators.iter() {
                    // Coordinator
                    let mut coordinator =
                        mocks::coordinator::Coordinator::new(identity.clone(), pks.clone(), *share);
                    debug!("Share index: {}", share.index);
                    coordinator.set_view(111);

                    // Application
                    let (mut app, app_mailbox) = mocks::application::Application::new();
                    mailboxes.insert(validator.clone(), app_mailbox.clone());

                    // Signer
                    let cfg = journal::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        partition: hex(validator),
                    };
                    let journal = Journal::init(runtime.clone(), cfg)
                        .await
                        .expect("Failed to initialize journal");
                    let (signer, signer_mailbox) = signer::Actor::new(
                        runtime.clone(),
                        journal,
                        signer::Config {
                            crypto: scheme.clone(),
                            application: app_mailbox.clone(),
                            collector: collector_mailbox.clone(),
                            coordinator,
                            mailbox_size: 1,
                            hasher: Sha256::default(),
                            namespace: b"test".to_vec(),
                            epoch_bounds: (1, 1),
                            prune_timeout: None,
                            rebroadcast_timeout: Some(Duration::from_secs(5)),
                        },
                    );

                    // Run the actors
                    runtime.spawn("app", async move { app.run(signer_mailbox).await });
                    let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                    runtime.spawn(
                        "signer",
                        async move { signer.run((a1, a2), (b1, b2)).await },
                    );
                }

                // For each validator, attempt to propose a payload every 250ms
                runtime.spawn("proposer", {
                    let runtime = runtime.clone();
                    async move {
                        let mut iter = 0;
                        let mut hasher = Sha256::default();
                        loop {
                            iter += 1;
                            for (validator, mailbox) in mailboxes.iter_mut() {
                                let payload = Bytes::from(format!(
                                    "hello world from validator {}, iter {}",
                                    hex(validator),
                                    iter
                                ));
                                hasher.update(&payload);
                                let digest = hasher.finalize();
                                mailbox.broadcast(digest).await;
                            }
                            runtime.sleep(Duration::from_millis(250)).await;
                        }
                    }
                });

                // Wait for the acknowledged height of each sequencer to reach 100
                let (collector_sender, collector_receiver) = oneshot::channel();
                runtime.spawn("collector", {
                    let mut collector = collector_mailbox.clone();
                    let runtime = runtime.clone();
                    async move {
                        loop {
                            let mut min_tip = u64::MAX;
                            for (v, _, _) in validators.iter() {
                                let tip = collector.get_tip(v.clone()).await.unwrap_or(0);
                                debug!("Collector: tip {}", tip);
                                min_tip = min_tip.min(tip);
                            }
                            if min_tip >= 100 {
                                collector_sender.send(()).unwrap();
                                break;
                            }
                            debug!("Collector: min tip {}", min_tip);
                            runtime.sleep(Duration::from_millis(100)).await;
                        }
                    }
                });

                collector_receiver.await.unwrap();
            }
        });
    }
}
