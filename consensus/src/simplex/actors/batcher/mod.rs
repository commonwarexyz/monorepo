mod actor;
mod ingress;
mod round;
mod verifier;

use crate::{
    types::{Epoch, ViewDelta},
    Reporter,
};
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
pub use ingress::{Mailbox, Message};
pub use round::Round;
pub use verifier::Verifier;

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
            actors::voter,
            elector::RoundRobin,
            mocks,
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, Scheme},
            types::{
                Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
                Nullify, Proposal, Vote,
            },
        },
        types::{Round, View},
        Viewable,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network},
        Recipients, Sender as _,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Quota, Runner};
    use commonware_utils::quorum;
    use futures::{channel::mpsc, StreamExt};
    use std::{num::NonZeroU32, time::Duration};

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn build_notarization<S: Scheme<Sha256Digest>>(
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

    fn build_nullification<S: Scheme<Sha256Digest>>(
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

    fn build_finalization<S: Scheme<Sha256Digest>>(
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

    fn certificate_forwarding_from_network<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n) as usize;
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Create a peer to inject certificates
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
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
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher
            let view = View::new(1);
            let active = batcher_mailbox.update(view, 0, View::zero()).await;
            assert!(active);

            // Build certificates
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            let notarization = build_notarization(&schemes, &namespace, &proposal, quorum);
            let nullification = build_nullification(&schemes, &namespace, round, quorum);
            let finalization = build_finalization(&schemes, &namespace, &proposal, quorum);

            // Send notarization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view)
            );

            // Send nullification from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification.clone())
                        .encode()
                        .into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Nullification(n), _) if n.view() == view)
            );

            // Send finalization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Finalization(finalization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Finalization(f), _) if f.view() == view)
            );
        });
    }

    #[test_traced]
    fn test_certificate_forwarding_from_network() {
        certificate_forwarding_from_network(bls12381_threshold::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_threshold::fixture::<MinSig, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinSig, _>);
        certificate_forwarding_from_network(ed25519::fixture);
    }

    fn quorum_votes_construct_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

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
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

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
                            Vote::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote via constructed message
            let our_vote = Notarize::sign(&schemes[0], &namespace, proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote))
                .await;

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(100)).await;

            // Should receive the leader's proposal first (participant 1 is leader)
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload"))
            );

            // Should receive notarization certificate from quorum of votes
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view));
        });
    }

    #[test_traced]
    fn test_quorum_votes_construct_certificate() {
        quorum_votes_construct_certificate(bls12381_threshold::fixture::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_threshold::fixture::<MinSig, _>);
        quorum_votes_construct_certificate(bls12381_multisig::fixture::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_multisig::fixture::<MinSig, _>);
        quorum_votes_construct_certificate(ed25519::fixture);
    }

    /// Test that if both votes and a certificate arrive, only one certificate is sent to voter.
    fn votes_and_certificate_deduplication<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

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
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Create an injector peer to send certificates (on channel 1)
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(injector_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

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
                            Vote::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote
            let our_vote = Notarize::sign(&schemes[0], &namespace, proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote)).await;

            // Give network time to deliver votes
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal (participant 1)
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(&output, voter::Message::Proposal(p) if p.view() == view));

            // Now send the certificate from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Should receive exactly one notarization
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view)
            );

            // Now send enough votes to reach quorum (this vote would complete quorum)
            let last_vote =
                Notarize::sign(&schemes[quorum_size - 1], &namespace, proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[quorum_size - 1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(last_vote).encode().into(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Try to receive another message (with timeout)
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
        votes_and_certificate_deduplication(bls12381_threshold::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_threshold::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(ed25519::fixture);
    }

    fn conflicting_votes_dont_produce_invalid_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 7;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Set up batcher as participant 0
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

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
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            let view = View::new(1);
            let leader = 1u32;
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(active);

            // Build TWO different proposals for the same view
            let round = Round::new(epoch, view);
            let proposal_a = Proposal::new(round, View::zero(), Sha256::hash(b"payload_a"));
            let proposal_b = Proposal::new(round, View::zero(), Sha256::hash(b"payload_b"));

            // Send vote for proposal_a from participant 1 (the leader)
            // This establishes proposal_a as the leader's proposal
            let leader_vote =
                Notarize::sign(&schemes[1], &namespace, proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(leader_vote).encode().into(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give time for leader's vote to arrive and set leader_proposal
            context.sleep(Duration::from_millis(50)).await;

            // The batcher should receive the leader's proposal
            let output = voter_receiver.next().await.unwrap();
            assert!(matches!(
                &output,
                voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"payload_a")
            ));

            // Now send votes for proposal_b from participants 2, 3, 4, 5 (4 votes)
            // These are for a DIFFERENT proposal and should be filtered out by BatchVerifier
            for i in 2..=5 {
                let vote = Notarize::sign(&schemes[i], &namespace, proposal_b.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Give time for votes to be processed
            context.sleep(Duration::from_millis(100)).await;

            // At this point we have:
            // - 1 vote for proposal_a (from leader, participant 1)
            // - 4 votes for proposal_b (from participants 2,3,4,5) - should be filtered
            // Total verified votes for proposal_a: only 1

            // Should NOT have a certificate yet
            let got_certificate = select! {
                _output = voter_receiver.next() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };
            assert!(
                !got_certificate,
                "Should not have certificate - only 1 vote for leader's proposal"
            );

            // Now send 4 more votes for proposal_a (from participants 0,2,3,4)
            // Participant 0 is us, use constructed
            let our_vote = Notarize::sign(&schemes[0], &namespace, proposal_a.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote))
                .await;

            // Participants 6 hasn't voted yet - use them for proposal_a
            let vote6 = Notarize::sign(&schemes[6], &namespace, proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[6] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(vote6).encode().into(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give time for processing
            context.sleep(Duration::from_millis(100)).await;

            // Still should not have certificate (only 3 votes for proposal_a: 0, 1, 6)
            let got_certificate = select! {
                _output = voter_receiver.next() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };
            assert!(
                !got_certificate,
                "Should not have certificate - only 3 votes for leader's proposal"
            );
        });
    }

    #[test_traced]
    fn test_conflicting_votes_dont_produce_invalid_certificate() {
        conflicting_votes_dont_produce_invalid_certificate(bls12381_threshold::fixture::<MinPk, _>);
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold::fixture::<MinSig, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_votes_dont_produce_invalid_certificate(ed25519::fixture);
    }

    /// Test that when we receive a leader's notarize vote AFTER setting the leader,
    /// the proposal is forwarded to the voter (when we are not the leader).
    fn proposal_forwarded_after_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor as participant 0
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) =
                oracle.control(leader_pk.clone()).register(0, TEST_QUOTA).await.unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            // We (participant 0) are NOT the leader
            let view = View::new(1);
            let leader = 1u32;
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(active);

            // Give time for update to process
            context.sleep(Duration::from_millis(10)).await;

            // Build proposal and leader's vote
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], &namespace, proposal.clone()).unwrap();

            // Now send the leader's vote - this should trigger proposal forwarding
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_after_leader_set() {
        proposal_forwarded_after_leader_set(bls12381_threshold::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(ed25519::fixture);
    }

    /// Test that when we receive a leader's notarize vote BEFORE setting the leader,
    /// the proposal is forwarded to the voter once the leader is set (when we are not the leader).
    fn proposal_forwarded_before_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor as participant 0
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) =
                oracle.control(leader_pk.clone()).register(0, TEST_QUOTA).await.unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher - but don't set leader yet
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Build proposal and leader's vote for view 1 with participant 1 as leader
            let view = View::new(1);
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], &namespace, proposal.clone()).unwrap();

            // Send the leader's vote BEFORE setting the leader
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Now set the leader - this should cause the proposal to be forwarded
            let leader = 1u32;
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(active);

            // Give time for batcher to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.next().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set (vote arrived before leader was known)"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_before_leader_set() {
        proposal_forwarded_before_leader_set(bls12381_threshold::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(ed25519::fixture);
    }

    /// Test that leader activity detection works correctly:
    /// 1. Early views (before skip_timeout) always return active
    /// 2. With enough recent views, activity is determined by leader's votes
    /// 3. With gaps in recent views (with sufficient data), returns inactive
    fn leader_activity_detection<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
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
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
                namespace: namespace.clone(),
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, _voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) =
                oracle.control(leader_pk.clone()).register(0, TEST_QUOTA).await.unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Test 1: Early views (before skip_timeout) should always return active
            // Views 1 through skip_timeout-1 are before the threshold
            let leader = 1u32;
            for v in 1..skip_timeout {
                let view = View::new(v);
                let active = batcher_mailbox.update(view, leader, View::zero()).await;
                assert!(active, "view {v} should be active (before skip_timeout)");
            }

            // Test 2: At view skip_timeout, we now have skip_timeout entries (views 1-5)
            // and the leader hasn't voted, so they should be marked inactive
            let view = View::new(skip_timeout);
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                !active,
                "view {skip_timeout} should be inactive (leader hasn't voted in {skip_timeout} views)"
            );

            // Test 3: Send a vote from the leader for the current view (view 5)
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], &namespace, proposal).unwrap();
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Test 4: Advance to view skip_timeout + 1 (view 6)
            // Leader voted in view 5, which is in the recent window, so should be active
            let view = View::new(skip_timeout + 1);
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                active,
                "view {} should be active (leader voted in view {})",
                skip_timeout + 1,
                skip_timeout
            );

            // Test 5: Jump far ahead to create a gap in recent views
            // Skip from view 6 to view 100 (this creates a gap where we don't have
            // data for views 7-99). The activity check looks at the last skip_timeout
            // rounds we have data for, so the leader's vote in view 5 is still visible.
            let view = View::new(100);
            let active = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                active,
                "view 100 should be active (leader voted in view 5, still in last {skip_timeout} rounds)"
            );
        });
    }

    #[test_traced]
    fn test_leader_activity_detection() {
        leader_activity_detection(bls12381_threshold::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_threshold::fixture::<MinSig, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinSig, _>);
        leader_activity_detection(ed25519::fixture);
    }

    /// Test that votes above finalized trigger verification/construction,
    /// but votes at or below finalized do not.
    fn votes_skipped_for_finalized_views<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
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
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
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

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

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
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Start with finalized=0, current=1 (view 1 is above finalized)
            let view1 = View::new(1);
            let view2 = View::new(2);
            let leader = 1u32;

            let active = batcher_mailbox.update(view1, leader, View::zero()).await;
            assert!(active);

            // Part 1: Send NOTARIZE votes for view 1 (above finalized=0, should succeed)
            let round1 = Round::new(epoch, view1);
            let proposal1 = Proposal::new(round1, View::zero(), Sha256::hash(b"payload1"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], &namespace, proposal1.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own notarize vote for view 1 via constructed
            let our_notarize = Notarize::sign(&schemes[0], &namespace, proposal1.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_notarize))
                .await;

            // Should receive a notarization certificate (view 1 is above finalized=0)
            loop {
                let output = voter_receiver.next().await.unwrap();
                match output {
                    voter::Message::Proposal(_) => continue,
                    voter::Message::Verified(Certificate::Notarization(n), _) => {
                        assert_eq!(
                            n.view(),
                            view1,
                            "Should construct notarization for view above finalized"
                        );
                        break;
                    }
                    _ => panic!("Unexpected message type"),
                }
            }

            // Part 2: Advance finalized to view 2
            // Now test NOTARIZE votes for view 2 which should NOT be processed (at finalized=2)
            let view3 = View::new(3);
            let active = batcher_mailbox.update(view3, leader, view2).await;
            assert!(active);

            // Send NOTARIZE votes for view 2 (now at finalized=2, should NOT succeed)
            let round2 = Round::new(epoch, view2);
            let proposal2 = Proposal::new(round2, view1, Sha256::hash(b"payload2"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], &namespace, proposal2.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode().into(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own notarize vote for view 2 via constructed
            let our_notarize2 = Notarize::sign(&schemes[0], &namespace, proposal2.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_notarize2))
                .await;

            // Should NOT receive any certificate for the finalized view
            select! {
                msg = voter_receiver.next() => {
                    match msg {
                        Some(voter::Message::Proposal(_)) => {},
                        Some(voter::Message::Verified(cert, _)) if cert.view() == view2 => {
                            panic!("should not receive any certificate for the finalized view");
                        },
                        _ => {},
                    }
                },
                _ = context.sleep(Duration::from_millis(200)) => { },
            };
        });
    }

    #[test_traced]
    fn test_votes_skipped_for_finalized_views() {
        votes_skipped_for_finalized_views(bls12381_threshold::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_threshold::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(ed25519::fixture);
    }
}
