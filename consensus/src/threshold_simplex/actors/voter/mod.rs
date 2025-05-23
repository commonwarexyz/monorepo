mod actor;
mod ingress;

use std::time::Duration;

use crate::{
    threshold_simplex::types::{Activity, Context, View},
    Automaton, Relay, Reporter, ThresholdSupervisor,
};
pub use actor::Actor;
use commonware_cryptography::{bls12381::primitives::group, Digest};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Scheme};
use commonware_p2p::Blocker;
pub use ingress::{Mailbox, Message};

pub struct Config<
    C: Scheme,
    B: Blocker,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Context<D>>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<Seed = V::Signature, Index = View, Share = group::Share>,
> {
    pub crypto: C,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,
    pub supervisor: S,

    pub partition: String,
    pub compression: Option<u8>,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub replay_concurrency: usize,
    pub replay_buffer: usize,
    pub write_buffer: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_simplex::{
        actors::{batcher, resolver},
        mocks,
        types::{Finalization, Finalize, Notarization, Notarize, Proposal, Viewable, Voter},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{ops::threshold_signature_recover, variant::MinSig},
        },
        hash, Ed25519, Sha256, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network},
        Receiver, Recipients, Sender,
    };
    use commonware_runtime::{deterministic, Metrics, Runner, Spawner};
    use commonware_utils::quorum;
    use futures::{channel::mpsc, StreamExt};
    use std::time::Duration;
    use std::{collections::BTreeMap, sync::Arc};

    /// Trigger processing of an uninteresting view from the resolver after
    /// jumping ahead to a new finalize view:
    ///
    /// 1. Send a finalization for view 100.
    /// 2. Send a notarization from resolver for view 50 (should be ignored).
    /// 3. Send a finalization for view 300 (should be processed).
    #[test_traced]
    fn test_stale_backfill() {
        let n = 5;
        let threshold = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
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

            // Derive threshold shares
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n, threshold);

            // Initialize voter actor
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let mut participants = BTreeMap::new();
            participants.insert(
                0,
                (polynomial.clone(), validators.clone(), shares[0].clone()),
            );
            let supervisor_config = mocks::supervisor::Config::<_, MinSig> {
                namespace: namespace.clone(),
                participants,
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
            let cfg = Config {
                crypto: scheme,
                blocker: oracle.control(validator.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                supervisor,
                partition: "test".to_string(),
                compression: Some(3),
                namespace: namespace.clone(),
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(5),
                activity_timeout: 10,
                replay_concurrency: 1,
                replay_buffer: 1024 * 1024,
                write_buffer: 1024 * 1024,
            };
            let (actor, mut mailbox) = Actor::new(context.clone(), cfg);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(1);
            let resolver = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(1024);
            let batcher = batcher::Mailbox::new(batcher_sender);

            // Create a dummy network mailbox
            let peer = schemes[1].public_key();
            let (pending_sender, _pending_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            let (mut _peer_pending_sender, mut _peer_pending_receiver) =
                oracle.register(peer.clone(), 0).await.unwrap();
            let (mut peer_recovered_sender, mut peer_recovered_receiver) =
                oracle.register(peer.clone(), 1).await.unwrap();
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

            // Run the actor
            actor.start(
                batcher,
                resolver,
                pending_sender,
                recovered_sender,
                recovered_receiver,
            );

            // Wait for batcher to be notified
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    active,
                } => {
                    assert_eq!(current, 1);
                    assert_eq!(finalized, 0);
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Drain the peer_recovered_receiver
            context
                .with_label("peer_recovered_receiver")
                .spawn(|_| async move {
                    loop {
                        peer_recovered_receiver.recv().await.unwrap();
                    }
                });

            // Send finalization over network (view 100)
            let payload = hash(b"test");
            let proposal = Proposal::new(100, 50, payload);
            let partials: Vec<_> = shares
                .iter()
                .map(|share| {
                    let notarize = Notarize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    let finalize = Finalize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    (finalize.proposal_signature, notarize.seed_signature)
                })
                .collect();
            let proposal_partials = partials
                .iter()
                .map(|(proposal_signature, _)| proposal_signature);
            let proposal_signature =
                threshold_signature_recover::<MinSig, _>(threshold, proposal_partials).unwrap();
            let seed_partials = partials.iter().map(|(_, seed_signature)| seed_signature);
            let seed_signature =
                threshold_signature_recover::<MinSig, _>(threshold, seed_partials).unwrap();
            let finalization =
                Finalization::<MinSig, _>::new(proposal, proposal_signature, seed_signature);
            let msg = Voter::Finalization(finalization).encode().into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        active,
                    } => {
                        assert_eq!(current, 101);
                        assert_eq!(finalized, 100);
                        active.send(true).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 100);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send old notarization from resolver that should be ignored (view 50)
            let payload = hash(b"test2");
            let proposal = Proposal::new(50, 49, payload);
            let partials: Vec<_> = shares
                .iter()
                .map(|share| {
                    let notarize = Notarize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    let finalize = Finalize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    (finalize.proposal_signature, notarize.seed_signature)
                })
                .collect();
            let proposal_partials = partials
                .iter()
                .map(|(proposal_signature, _)| proposal_signature);
            let proposal_signature =
                threshold_signature_recover::<MinSig, _>(threshold, proposal_partials).unwrap();
            let seed_partials = partials.iter().map(|(_, seed_signature)| seed_signature);
            let seed_signature =
                threshold_signature_recover::<MinSig, _>(threshold, seed_partials).unwrap();
            let notarization = Notarization::new(proposal, proposal_signature, seed_signature);
            mailbox
                .verified(vec![Voter::Notarization(notarization)])
                .await;

            // Send new finalization (view 300)
            let payload = hash(b"test3");
            let proposal = Proposal::new(300, 100, payload);
            let partials: Vec<_> = shares
                .iter()
                .map(|share| {
                    let notarize = Notarize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    let finalize = Finalize::<MinSig, _>::sign(&namespace, share, proposal.clone());
                    (finalize.proposal_signature, notarize.seed_signature)
                })
                .collect();
            let proposal_partials = partials
                .iter()
                .map(|(proposal_signature, _)| proposal_signature);
            let proposal_signature =
                threshold_signature_recover::<MinSig, _>(threshold, proposal_partials).unwrap();
            let seed_partials = partials.iter().map(|(_, seed_signature)| seed_signature);
            let seed_signature =
                threshold_signature_recover::<MinSig, _>(threshold, seed_partials).unwrap();
            let finalization =
                Finalization::<MinSig, _>::new(proposal, proposal_signature, seed_signature);
            let msg = Voter::Finalization(finalization).encode().into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        active,
                    } => {
                        assert_eq!(current, 301);
                        assert_eq!(finalized, 300);
                        active.send(true).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 300);
                }
                _ => panic!("unexpected progress"),
            }
        });
    }

    /// Process an interesting view below the oldest tracked view:
    ///
    /// 1. Advance last_finalized to a view 50.
    /// 2. Ensure self.views contains a view V_A (45) which is interesting,
    ///    and becomes the 'oldest' view when prune_views runs, setting the journal floor.
    ///    Crucially, ensure there's a "gap" so that V_A is not LF - activity_timeout.
    /// 3. Let prune_views run, setting the journal floor to V_A.
    /// 4. Inject a message for V_B such that V_B < V_A but V_B is still "interesting"
    ///    relative to the current last_finalized.
    #[test_traced]
    fn test_append_old_interesting_view() {
        let n = 5;
        let threshold = quorum(n);
        let namespace = b"test_prune_panic".to_vec();
        let activity_timeout: View = 10;
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
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
                validators.push(scheme.public_key());
                schemes.push(scheme);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());

            // Derive threshold shares
            let (polynomial, shares) =
                ops::generate_shares::<_, MinSig>(&mut context, None, n, threshold);

            // Setup the target Voter actor (validator 0)
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let mut participants = BTreeMap::new();
            participants.insert(
                0,
                (polynomial.clone(), validators.clone(), shares[0].clone()),
            );
            let supervisor_config = mocks::supervisor::Config::<_, MinSig> {
                namespace: namespace.clone(),
                participants,
            };
            let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let app_config = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_config);
            actor.start();
            let voter_config = Config {
                crypto: scheme.clone(),
                blocker: oracle.control(validator.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                supervisor: supervisor.clone(),
                partition: format!("voter_actor_test_{}", validator),
                compression: None,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_millis(1000),
                nullify_retry: Duration::from_millis(1000),
                activity_timeout,
                replay_concurrency: 1,
                replay_buffer: 10240,
                write_buffer: 10240,
            };
            let (actor, _mailbox) = Actor::new(context.clone(), voter_config);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(1);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(10);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Create a dummy network mailbox
            let peer = schemes[1].public_key();
            let (pending_sender, _pending_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            let (mut _peer_pending_sender, mut _peer_pending_receiver) =
                oracle.register(peer.clone(), 0).await.unwrap();
            let (mut peer_recovered_sender, mut peer_recovered_receiver) =
                oracle.register(peer.clone(), 1).await.unwrap();
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

            // Start the actor
            actor.start(
                batcher_mailbox,
                resolver_mailbox,
                pending_sender,
                recovered_sender,
                recovered_receiver,
            );

            // Wait for batcher to be notified
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    active,
                } => {
                    assert_eq!(current, 1);
                    assert_eq!(finalized, 0);
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Drain the peer_recovered_receiver
            context
                .with_label("peer_recovered_receiver")
                .spawn(|_| async move {
                    loop {
                        peer_recovered_receiver.recv().await.unwrap();
                    }
                });

            // Establish Prune Floor (50 - 10 + 5 = 45)
            //
            // Theoretical interesting floor is 50-10 = 40.
            // We want journal pruned at 45.
            let lf_target: View = 50;
            let journal_floor_target: View = lf_target - activity_timeout + 5;

            // Send Finalization to advance last_finalized
            let proposal_lf = Proposal::new(lf_target, lf_target - 1, hash(b"test"));
            let finalization_lf_sigs = shares
                .iter()
                .take(threshold as usize)
                .map(|s| {
                    let notarize = Notarize::<MinSig, _>::sign(&namespace, s, proposal_lf.clone());
                    let finalize = Finalize::<MinSig, _>::sign(&namespace, s, proposal_lf.clone());
                    (finalize.proposal_signature, notarize.seed_signature)
                })
                .collect::<Vec<_>>();
            let final_prop_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                finalization_lf_sigs.iter().map(|(ps, _)| ps),
            )
            .unwrap();
            let final_seed_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                finalization_lf_sigs.iter().map(|(_, ss)| ss),
            )
            .unwrap();
            let msg = Voter::Finalization(Finalization::<MinSig, _>::new(
                proposal_lf,
                final_prop_sig,
                final_seed_sig,
            ))
            .encode()
            .into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        active,
                    } => {
                        assert_eq!(current, 51);
                        assert_eq!(finalized, 50);
                        active.send(true).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 50);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send a Notarization for `journal_floor_target` to ensure it's in `actor.views`
            let proposal_jft = Proposal::new(
                journal_floor_target,
                journal_floor_target - 1,
                hash(b"test2"),
            );
            let notarization_jft_sigs = shares
                .iter()
                .take(threshold as usize)
                .map(|s| Notarize::<MinSig, _>::sign(&namespace, s, proposal_jft.clone()))
                .collect::<Vec<_>>();
            let not_prop_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                notarization_jft_sigs.iter().map(|n| &n.proposal_signature),
            )
            .unwrap();
            let not_seed_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                notarization_jft_sigs.iter().map(|n| &n.seed_signature),
            )
            .unwrap();
            let notarization_for_floor =
                Notarization::<MinSig, _>::new(proposal_jft, not_prop_sig, not_seed_sig);
            let msg = Voter::Notarization(notarization_for_floor).encode().into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send notarization");

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Notarized { notarization } => {
                    assert_eq!(notarization.view(), journal_floor_target);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send notarization below oldest interesting view (42)
            //
            // problematic_view (42) < journal_floor_target (45)
            // interesting(42, false) -> 42 + AT(10) >= LF(50) -> 52 >= 50
            let problematic_view: View = journal_floor_target - 3;
            let proposal_bft =
                Proposal::new(problematic_view, problematic_view - 1, hash(b"test3"));
            let notarization_bft_sigs = shares
                .iter()
                .take(threshold as usize)
                .map(|s| Notarize::<MinSig, _>::sign(&namespace, s, proposal_bft.clone()))
                .collect::<Vec<_>>();
            let not_prop_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                notarization_bft_sigs.iter().map(|n| &n.proposal_signature),
            )
            .unwrap();
            let not_seed_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                notarization_bft_sigs.iter().map(|n| &n.seed_signature),
            )
            .unwrap();
            let notarization_for_bft =
                Notarization::<MinSig, _>::new(proposal_bft, not_prop_sig, not_seed_sig);
            let msg = Voter::Notarization(notarization_for_bft).encode().into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send notarization");

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Notarized { notarization } => {
                    assert_eq!(notarization.view(), problematic_view);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send Finalization to new view (100)
            let proposal_lf = Proposal::new(100, 99, hash(b"test4"));
            let finalization_lf_sigs = shares
                .iter()
                .take(threshold as usize)
                .map(|s| {
                    let notarize = Notarize::<MinSig, _>::sign(&namespace, s, proposal_lf.clone());
                    let finalize = Finalize::<MinSig, _>::sign(&namespace, s, proposal_lf.clone());
                    (finalize.proposal_signature, notarize.seed_signature)
                })
                .collect::<Vec<_>>();
            let final_prop_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                finalization_lf_sigs.iter().map(|(ps, _)| ps),
            )
            .unwrap();
            let final_seed_sig = threshold_signature_recover::<MinSig, _>(
                threshold,
                finalization_lf_sigs.iter().map(|(_, ss)| ss),
            )
            .unwrap();
            let msg = Voter::Finalization(Finalization::<MinSig, _>::new(
                proposal_lf,
                final_prop_sig,
                final_seed_sig,
            ))
            .encode()
            .into();
            peer_recovered_sender
                .send(Recipients::All, msg, true)
                .await
                .expect("failed to send finalization");

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        active,
                    } => {
                        assert_eq!(current, 101);
                        assert_eq!(finalized, 100);
                        active.send(true).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                resolver::Message::Finalized { view } => {
                    assert_eq!(view, 100);
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }
}
