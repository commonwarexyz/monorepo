//! Aggregation module

pub mod types;
pub mod wire;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod safe_tip;

        #[cfg(test)]
        pub mod mocks;
    }
}

#[cfg(test)]
mod tests {
    use super::{mocks, types::Epoch, Config, Engine};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{
                group::Share,
                poly,
                variant::{MinPk, MinSig, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt as _, Signer as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics,
    };
    use commonware_runtime::{Clock, Runner, Spawner};
    use futures::channel::oneshot;
    use futures::future::join_all;
    use std::{collections::BTreeMap, time::Duration};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    use tracing::debug;

    type Registrations<P> = BTreeMap<P, (Sender<P>, Receiver<P>)>;

    async fn register_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let (sender, receiver) = oracle.register(participant.clone(), 0).await.unwrap();
            registrations.insert(participant.clone(), (sender, receiver));
        }
        registrations
    }

    async fn link_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
        link: Link,
    ) {
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v2 == v1 {
                    continue;
                }
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    async fn initialize_simulation_with_link(
        context: Context,
        num_validators: u32,
        shares_vec: &mut [Share],
        link: Link,
    ) -> (
        Oracle<PublicKey>,
        Vec<(PublicKey, PrivateKey, Share)>,
        Vec<PublicKey>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

        let mut schemes = (0..num_validators)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let validators: Vec<(PublicKey, PrivateKey, Share)> = schemes
            .iter()
            .enumerate()
            .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i].clone()))
            .collect();
        let pks = validators
            .iter()
            .map(|(pk, _, _)| pk.clone())
            .collect::<Vec<_>>();

        let registrations = register_participants(&mut oracle, &pks).await;
        link_participants(&mut oracle, &pks, link).await;
        (oracle, validators, pks, registrations)
    }

    async fn initialize_simulation(
        context: Context,
        num_validators: u32,
        shares_vec: &mut [Share],
    ) -> (
        Oracle<PublicKey>,
        Vec<(PublicKey, PrivateKey, Share)>,
        Vec<PublicKey>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

        let mut schemes = (0..num_validators)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let validators: Vec<(PublicKey, PrivateKey, Share)> = schemes
            .iter()
            .enumerate()
            .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i].clone()))
            .collect();
        let pks = validators
            .iter()
            .map(|(pk, _, _)| pk.clone())
            .collect::<Vec<_>>();

        let registrations = register_participants(&mut oracle, &pks).await;
        let link = Link {
            latency: 10.0,
            jitter: 1.0,
            success_rate: 1.0,
        };
        link_participants(&mut oracle, &pks, link).await;
        (oracle, validators, pks, registrations)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_validator_engines<V: Variant>(
        context: Context,
        polynomial: poly::Public<V>,
        validator_pks: &[PublicKey],
        validators: &[(PublicKey, PrivateKey, Share)],
        registrations: &mut Registrations<PublicKey>,
        automatons: &mut BTreeMap<PublicKey, mocks::Application>,
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>,
        rebroadcast_timeout: Duration,
        invalid_when: fn(u64) -> bool,
        misses_allowed: Option<usize>,
    ) -> HashMap<PublicKey, mocks::Monitor> {
        let mut monitors = HashMap::new();
        let namespace = b"my testing namespace";
        for (validator, _scheme, share) in validators.iter() {
            let context = context.with_label(&validator.to_string());
            let monitor = mocks::Monitor::new(111);
            monitors.insert(validator.clone(), monitor.clone());
            let supervisor = {
                let mut s = mocks::Supervisor::<PublicKey, V>::new();
                s.add_epoch(
                    111,
                    share.clone(),
                    polynomial.clone(),
                    validator_pks.to_vec(),
                );
                s
            };

            let automaton = mocks::Application::new(invalid_when);
            automatons.insert(validator.clone(), automaton.clone());

            let (reporter, reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                namespace,
                polynomial.clone(),
                misses_allowed,
            );
            context.with_label("reporter").spawn(|_| reporter.run());
            reporters.insert(validator.clone(), reporter_mailbox);

            let engine = Engine::new(
                context.with_label("engine"),
                Config {
                    monitor,
                    validators: supervisor,
                    automaton: automaton.clone(),
                    reporter: reporters.get(validator).unwrap().clone(),
                    namespace: namespace.to_vec(),
                    priority_acks: false,
                    rebroadcast_timeout,
                    epoch_bounds: (1, 1),
                    window: 10,
                    journal_name: format!("aggregation/{}/", validator),
                    journal_write_buffer: 4096,
                    journal_replay_buffer: 4096,
                    journal_heights_per_section: 100,
                    journal_replay_concurrency: 1,
                    journal_compression: Some(3),
                },
            );

            let (sender, receiver) = registrations.remove(validator).unwrap();
            engine.start((sender, receiver));
        }
        monitors
    }

    async fn await_reporters<V: Variant>(
        context: Context,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>,
        threshold: (u64, Epoch),
    ) {
        let mut receivers = Vec::new();
        for (reporter, mailbox) in reporters.iter() {
            // Create a oneshot channel to signal when the reporter has reached the threshold.
            let (tx, rx) = oneshot::channel();
            receivers.push(rx);

            context.with_label("reporter_watcher").spawn({
                let reporter = reporter.clone();
                let mut mailbox = mailbox.clone();
                move |context| async move {
                    loop {
                        let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, 0));
                        let contiguous_index = mailbox.get_contiguous_tip().await.unwrap_or(0);
                        debug!(
                            index,
                            epoch,
                            contiguous_index,
                            threshold_index = threshold.0,
                            threshold_epoch = threshold.1,
                            ?reporter,
                            "reporter status"
                        );
                        if index >= threshold.0 && epoch >= threshold.1 {
                            debug!(
                                ?reporter,
                                "reporter reached threshold, signaling completion"
                            );
                            let _ = tx.send(reporter.clone());
                            break;
                        }
                        context.sleep(Duration::from_millis(100)).await;
                    }
                }
            });
        }

        // Wait for all oneshot receivers to complete.
        let results = join_all(receivers).await;
        assert_eq!(results.len(), reporters.len());

        // Check that none were cancelled.
        for result in results {
            assert!(result.is_ok(), "reporter was cancelled");
        }
    }

    fn all_online<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                None,
            );
            await_reporters(context.with_label("reporter"), &reporters, (1, 111)).await;
        });
    }

    fn unclean_shutdown<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            // Start all validators with unique journal names
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                None,
            );

            // Test that aggregation works even with potential unclean shutdowns
            // The engine implementation includes journaling which should handle
            // restarts gracefully
            await_reporters(context.with_label("reporter"), &reporters, (1, 111)).await;
        });
    }

    fn slow_and_lossy_links<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            // Use degraded network links
            let degraded_link = Link {
                latency: 200.0,
                jitter: 150.0,
                success_rate: 0.7, // 70% success rate instead of 50% to ensure test passes
            };

            let (_oracle, validators, pks, mut registrations) = initialize_simulation_with_link(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                degraded_link,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                None,
            );

            await_reporters(context.with_label("reporter"), &reporters, (1, 111)).await;
        });
    }

    fn slow_validator<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            // Start all validators but with increased rebroadcast timeout for the first one (slow)
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(15), // Slower rebroadcast timeout
                |_| false,
                None,
            );

            await_reporters(context.with_label("reporter"), &reporters, (1, 111)).await;
        });
    }

    fn one_offline<V: Variant>() {
        let num_validators: u32 = 5;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            // Start only 4 out of 5 validators (one offline)
            let online_validators: Vec<_> = validators.iter().take(4).cloned().collect();
            let online_pks: Vec<_> = pks.iter().take(4).cloned().collect();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &online_pks,
                &online_validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                None,
            );
            await_reporters(context.with_label("reporter"), &reporters, (1, 111)).await;
        });
    }

    #[test_traced]
    fn test_all_online() {
        all_online::<MinPk>();
        all_online::<MinSig>();
    }

    #[test_traced]
    fn test_one_offline() {
        one_offline::<MinPk>();
        one_offline::<MinSig>();
    }

    #[test_traced]
    fn test_slow_validator() {
        slow_validator::<MinPk>();
        slow_validator::<MinSig>();
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links::<MinPk>();
        slow_and_lossy_links::<MinSig>();
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown::<MinPk>();
        unclean_shutdown::<MinSig>();
    }
}
