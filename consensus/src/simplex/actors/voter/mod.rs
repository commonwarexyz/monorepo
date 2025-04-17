mod actor;
mod ingress;

use crate::simplex::types::{Activity, Context, View};
use crate::{Automaton, Supervisor};
use crate::{Relay, Reporter};
pub use actor::Actor;
use commonware_cryptography::{Digest, Scheme};
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<C::Signature, D>>,
    S: Supervisor<Index = View>,
> {
    pub crypto: C,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub max_participants: usize,
    pub activity_timeout: View,
    pub skip_timeout: View,
    pub replay_concurrency: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        actors::resolver,
        mocks,
        types::{
            finalize_namespace, notarize_namespace, Finalization, Finalize, Notarization, Notarize,
            Proposal, Voter,
        },
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{hash, Ed25519, Sha256, Signer};
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network},
        Receiver, Recipients, Sender,
    };
    use commonware_runtime::{deterministic::Executor, Metrics, Runner, Spawner};
    use commonware_storage::journal::variable::{Config as JConfig, Journal};
    use commonware_utils::quorum;
    use futures::{channel::mpsc, StreamExt};
    use std::time::Duration;
    use std::{collections::BTreeMap, sync::Arc};

    #[test_traced]
    fn test_stale_backfill() {
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let namespace = b"consensus".to_vec();
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Get participants
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

            // Initialize voter actor
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let supervisor_config: mocks::supervisor::Config<Ed25519> = mocks::supervisor::Config {
                namespace: namespace.clone(),
                participants: view_validators.clone(),
            };
            let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
            let relay = Arc::new(mocks::relay::Relay::new());
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
                partition: "test".to_string(),
            };
            let journal = Journal::init(context.with_label("journal"), cfg)
                .await
                .expect("unable to create journal");

            let cfg = Config {
                crypto: scheme,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                supervisor,
                namespace: namespace.clone(),
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(5),
                max_participants: n as usize,
                activity_timeout: 10,
                skip_timeout: 10,
                replay_concurrency: 1,
            };
            let (actor, mut mailbox) = Actor::new(context.clone(), journal, cfg);

            // Create a dummy backfiller mailbox
            let (backfiller_sender, mut backfiller_receiver) = mpsc::channel(1);
            let backfiller = resolver::Mailbox::new(backfiller_sender);

            // Create a dummy network mailbox
            let peer = schemes[1].public_key();
            let (voter_sender, voter_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (mut peer_sender, mut peer_receiver) =
                oracle.register(peer.clone(), 0).await.unwrap();
            oracle
                .add_link(
                    validator.clone(),
                    peer.clone(),
                    Link {
                        latency: 0.0,
                        jitter: 0.0,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    peer,
                    validator,
                    Link {
                        latency: 0.0,
                        jitter: 0.0,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Drain peer receiver
            context.with_label("peer_receiver").spawn(|_| async move {
                loop {
                    peer_receiver.recv().await.unwrap();
                }
            });

            // Run the actor
            actor.start(backfiller, voter_sender, voter_receiver);

            // Send finalization over network (view 100)
            let finalize_namespace = finalize_namespace(&namespace);
            let payload = hash(b"test");
            let proposal = Proposal::new(100, 50, payload);
            let mut signatures = Vec::new();
            for i in 0..threshold {
                let finalization = Finalize::sign(
                    &mut schemes[i as usize],
                    i,
                    proposal.clone(),
                    &finalize_namespace,
                );
                signatures.push(finalization.signature);
            }
            let finalization = Finalization::new(proposal, signatures);
            let msg = Voter::Finalization(finalization).encode().into();
            peer_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for backfiller to be notified
            let msg = backfiller_receiver
                .next()
                .await
                .expect("failed to receive backfiller message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 100);
                }
                _ => panic!("unexpected backfiller message"),
            }

            // Send old notarization from backfiller that should be ignored (view 50)
            let notarize_namespace = notarize_namespace(&namespace);
            let payload = hash(b"test2");
            let proposal = Proposal::new(50, 49, payload);
            let mut signatures = Vec::new();
            for i in 0..threshold {
                let notarization = Notarize::sign(
                    &mut schemes[i as usize],
                    i,
                    proposal.clone(),
                    &notarize_namespace,
                );
                signatures.push(notarization.signature);
            }
            let notarization = Notarization::new(proposal, signatures);
            mailbox.notarization(notarization).await;

            // Send new finalization (view 300)
            let payload = hash(b"test3");
            let proposal = Proposal::new(300, 100, payload);
            let mut signatures = Vec::new();
            for i in 0..threshold {
                let finalization = Finalize::sign(
                    &mut schemes[i as usize],
                    i,
                    proposal.clone(),
                    &finalize_namespace,
                );
                signatures.push(finalization.signature);
            }
            let finalization = Finalization::new(proposal, signatures);
            let msg = Voter::Finalization(finalization).encode().into();
            peer_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for backfiller to be notified
            let msg = backfiller_receiver
                .next()
                .await
                .expect("failed to receive backfiller message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 300);
                }
                _ => panic!("unexpected progress"),
            }
        });
    }
}
