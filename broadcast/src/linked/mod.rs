use commonware_cryptography::PublicKey;

mod actors;
mod config;
mod encoder;
mod mocks;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

pub mod engine;

pub type Index = u64;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Clone)]
pub struct Context {
    pub sequencer: PublicKey,
    pub index: Index,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::{config::Config, engine::Engine, mocks};
    use commonware_cryptography::{bls12381::dkg::ops, Ed25519, PublicKey, Scheme, Sha256};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic::Executor, Runner, Spawner};
    use prometheus_client::registry::Registry;

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

    #[test]
    fn test_signer() {
        let num_validators = 4;
        let quorum = 3;
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        let (identity, shares_vec) =
            ops::generate_shares(&mut runtime, None, num_validators, quorum);

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
                let mut validators = Vec::new();
                let mut shares = HashMap::new();
                let mut schemes = HashMap::new();
                for i in 0..num_validators {
                    let scheme = Ed25519::from_seed(i as u64);
                    let pk = scheme.public_key();
                    validators.push(pk.clone());
                    schemes.insert(pk.clone(), scheme);
                    shares.insert(pk, shares_vec[i as usize]);
                }
                validators.sort();
                let mut registrations = register_validators(&mut oracle, &validators).await;
                let link = Link {
                    latency: 10.0,
                    jitter: 1.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &validators, Action::Link(link), None).await;

                // Create engines
                let mut engine_handlers = Vec::new();
                for validator in validators.iter() {
                    // Supervisor
                    let share = shares.remove(validator).unwrap();
                    let supervisor = mocks::supervisor::Supervisor::new(
                        identity.clone(),
                        validators.clone(),
                        share,
                    );
                    let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();

                    // Engine
                    let scheme = schemes.get(validator).unwrap().clone();
                    let cfg = Config {
                        crypto: scheme.clone(),
                        supervisor,
                        mailbox_size: 1,
                        hasher: Sha256::default(),
                        share,
                        namespace: b"test".to_vec(),
                    };
                    let engine = Engine::new(runtime.clone(), cfg);
                    let engine_handler = runtime.spawn("engine", engine.run((a1, a2), (b1, b2)));
                    engine_handlers.push(engine_handler);
                }
            }
        });
    }
}
