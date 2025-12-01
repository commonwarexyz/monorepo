mod actor;
mod ingress;

use crate::{
    simplex::signing_scheme::Scheme,
    types::{Epoch, ViewDelta},
    Reporter,
};
pub use actor::Actor;
use commonware_p2p::Blocker;
pub use ingress::{BatcherOutput, Mailbox, Message};

pub struct Config<S: Scheme, B: Blocker, R: Reporter> {
    pub scheme: S,

    pub blocker: B,
    pub reporter: R,

    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::{
                self,
                fixtures::{bls12381_multisig, ed25519, Fixture},
            },
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
                Voter,
            },
        },
        types::{Round, View},
        Viewable,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        ed25519,
        sha256::Digest as Sha256Digest,
        Hasher as _, PrivateKeyExt, Sha256, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network},
        Recipients, Sender as _,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::quorum;
    use futures::{channel::mpsc, StreamExt};
    use std::time::Duration;

    fn build_notarization<S: Scheme>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Notarization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &votes)
            .expect("notarization requires a quorum of votes")
    }

    fn build_nullification<S: Scheme>(
        schemes: &[S],
        namespace: &[u8],
        round: Round,
        count: usize,
    ) -> Nullification<S> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, round).unwrap())
            .collect();
        Nullification::from_nullifies(&schemes[0], &votes)
            .expect("nullification requires a quorum of votes")
    }

    fn build_finalization<S: Scheme>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Finalization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Finalize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &votes)
            .expect("finalization requires a quorum of votes")
    }

    /// Test that certificates received from network are forwarded to voter.
    fn certificate_forwarding_from_network<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                namespace: namespace.clone(),
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            // Create channels
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<BatcherOutput<S, Sha256Digest>>(1024);
            let (_pending_sender, pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (_recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();

            // Create an injector peer to send certificates
            let injector_pk = ed25519::PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1)
                .await
                .unwrap();

            // Set up link from injector to batcher
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_sender, pending_receiver, recovered_receiver);

            // Initialize batcher
            let view = View::new(1);
            let active = batcher_mailbox.update(view, 0, View::zero()).await;
            assert!(active);

            // Build certificates
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            let notarization = build_notarization(&schemes, &namespace, &proposal, quorum as usize);
            let nullification = build_nullification(&schemes, &namespace, round, quorum as usize);
            let finalization = build_finalization(&schemes, &namespace, &proposal, quorum as usize);

            // Send notarization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Voter::Notarization(notarization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, BatcherOutput::Notarization(n) if n.view() == view));

            // Send nullification from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Voter::<S, Sha256Digest>::Nullification(nullification.clone())
                        .encode()
                        .into(),
                    true,
                )
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, BatcherOutput::Nullification(n) if n.view() == view));

            // Send finalization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Voter::Finalization(finalization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, BatcherOutput::Finalization(f) if f.view() == view));
        });
    }

    #[test_traced]
    fn test_certificate_forwarding_from_network() {
        certificate_forwarding_from_network(bls12381_multisig::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_multisig::<MinSig, _>);
        certificate_forwarding_from_network(ed25519);
    }

    /// Test that a quorum of votes results in a certificate being forwarded to voter.
    fn quorum_votes_construct_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                namespace: namespace.clone(),
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            // Create channels for batcher
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<BatcherOutput<S, Sha256Digest>>(1024);
            let (_pending_sender, pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (_recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    // Batcher is participant 0, skip
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle.control(pk.clone()).register(0).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_sender, pending_receiver, recovered_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            // (so we can test leader proposal forwarding when vote arrives from network)
            let view = View::new(1);
            let leader = 1u32;
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(active);

            // Build proposal and votes
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send notarize votes from participants 1..quorum_size (excluding participant 0)
            // Participant 0's vote will be sent via mailbox.constructed()
            // Participant 1 is the leader, so their vote triggers proposal forwarding
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], &namespace, proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Voter::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote via constructed message
            let our_vote = Notarize::sign(&schemes[0], &namespace, proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Voter::Notarize(our_vote))
                .await;

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(100)).await;

            // Should receive the leader's proposal first (participant 1 is leader)
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(&output, BatcherOutput::Proposal { view: v, proposal: p } if *v == view && p.payload == Sha256::hash(b"test_payload"))
            );

            // Should receive notarization certificate from quorum of votes
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, BatcherOutput::Notarization(n) if n.view() == view));
        });
    }

    #[test_traced]
    fn test_quorum_votes_construct_certificate() {
        quorum_votes_construct_certificate(bls12381_multisig::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_multisig::<MinSig, _>);
        quorum_votes_construct_certificate(ed25519);
    }

    /// Test that if both votes and a certificate arrive, only one certificate is sent to voter.
    fn votes_and_certificate_deduplication<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                namespace: namespace.clone(),
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            // Create channels for batcher
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<BatcherOutput<S, Sha256Digest>>(1024);
            let (_pending_sender, pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (_recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle.control(pk.clone()).register(0).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Create an injector peer to send certificates (on channel 1)
            let injector_pk = ed25519::PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1)
                .await
                .unwrap();
            oracle
                .add_link(injector_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_sender, pending_receiver, recovered_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            let view = View::new(1);
            let leader = 1u32;
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(active);

            // Build proposal, votes, and certificate
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let notarization = build_notarization(&schemes, &namespace, &proposal, quorum_size);

            // Send some votes (but not enough for quorum), starting with leader (participant 1)
            // This triggers proposal forwarding
            for i in 1..quorum_size - 1 {
                let vote = Notarize::sign(&schemes[i], &namespace, proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Voter::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote
            let our_vote = Notarize::sign(&schemes[0], &namespace, proposal.clone()).unwrap();
            batcher_mailbox.constructed(Voter::Notarize(our_vote)).await;

            // Give network time to deliver votes
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal (participant 1)
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(&output, BatcherOutput::Proposal { view: v, .. } if *v == view));

            // Now send the certificate from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Voter::Notarization(notarization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Should receive exactly one notarization
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, BatcherOutput::Notarization(n) if n.view() == view));

            // Now send enough votes to reach quorum (this vote would complete quorum)
            let last_vote =
                Notarize::sign(&schemes[quorum_size - 1], &namespace, proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[quorum_size - 1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Voter::Notarize(last_vote).encode().into(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Try to receive another message (with timeout)
            use commonware_macros::select;
            let got_duplicate = select! {
                _ = voter_receiver.next() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };

            // Should not receive another notarization since we already have one
            assert!(!got_duplicate, "Should not receive duplicate certificate");
        });
    }

    #[test_traced]
    fn test_votes_and_certificate_deduplication() {
        votes_and_certificate_deduplication(bls12381_multisig::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_multisig::<MinSig, _>);
        votes_and_certificate_deduplication(ed25519);
    }
}
