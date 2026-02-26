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
use commonware_parallel::Strategy;
pub use ingress::{Mailbox, Message};
pub use round::Round;
pub use verifier::Verifier;

pub struct Config<S: Scheme, B: Blocker, R: Reporter, T: Strategy> {
    pub scheme: S,

    pub blocker: B,
    pub reporter: R,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub epoch: Epoch,
    pub mailbox_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            actors::voter,
            elector::RoundRobin,
            mocks, quorum,
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1, Scheme,
            },
            types::{
                Activity, Certificate, Finalization, Finalize, Notarization, Notarize,
                Nullification, Nullify, Proposal, Vote,
            },
        },
        types::{Participant, Round, View},
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
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Clock, Metrics, Quota, Runner};
    use commonware_utils::channel::mpsc;
    use std::{num::NonZeroU32, time::Duration};

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn build_notarization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Notarization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &votes, &Sequential)
            .expect("notarization requires a quorum of votes")
    }

    fn build_nullification<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        round: Round,
        count: usize,
    ) -> Nullification<S> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(&schemes[0], &votes, &Sequential)
            .expect("nullification requires a quorum of votes")
    }

    fn build_finalization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Finalization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &votes, &Sequential)
            .expect("finalization requires a quorum of votes")
    }

    fn certificate_forwarding_from_network<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let nullify = batcher_mailbox.update(view, Participant::new(0), View::zero()).await;
            assert!(nullify.is_none());

            // Build certificates
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            let notarization = build_notarization(&schemes, &proposal, quorum);
            let nullification = build_nullification(&schemes, round, quorum);
            let finalization = build_finalization(&schemes, &proposal, quorum);

            // Send notarization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view)
            );

            // Send nullification from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification.clone())
                        .encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Nullification(n), _) if n.view() == view)
            );

            // Send finalization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Finalization(finalization.clone()).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Finalization(f), _) if f.view() == view)
            );
        });
    }

    #[test_traced]
    fn test_certificate_forwarding_from_network() {
        certificate_forwarding_from_network(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certificate_forwarding_from_network(bls12381_threshold_std::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_threshold_std::fixture::<MinSig, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinSig, _>);
        certificate_forwarding_from_network(ed25519::fixture);
        certificate_forwarding_from_network(secp256r1::fixture);
    }

    /// Regression: an old notarization for view `V` is still forwarded to voter even
    /// after a nullification for `V` has been observed and current view moved to `V+1`.
    fn old_notarization_after_nullification_is_forwarded<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_old_notarization_after_nullification".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network.
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Get participants.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock.
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor.
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            // Create voter mailbox for batcher to send to.
            let (voter_sender, mut voter_receiver) =
                mpsc::channel::<voter::Message<S, Sha256Digest>>(1024);
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Create a peer to inject certificates.
            let injector_pk = PrivateKey::from_seed(1_000_001).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Set up link from injector to batcher.
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            // Start the batcher.
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher at target view.
            let target_view = View::new(1);
            let nullify = batcher_mailbox
                .update(target_view, Participant::new(0), View::zero())
                .await;
            assert!(nullify.is_none());

            // Build certificates for the same target view.
            let round = Round::new(epoch, target_view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let nullification = build_nullification(&schemes, round, quorum_size);
            let notarization = build_notarization(&schemes, &proposal, quorum_size);

            // Send nullification for V first.
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification).encode(),
                    true,
                )
                .await
                .unwrap();
            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Nullification(n), _) if n.view() == target_view)
            );

            // Simulate voter-driven view advance after nullification to V+1.
            let nullify = batcher_mailbox
                .update(target_view.next(), Participant::new(1), View::zero())
                .await;
            assert!(nullify.is_none());

            // Send old notarization for V after moving current view forward.
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization).encode(),
                    true,
                )
                .await
                .unwrap();
            context.sleep(Duration::from_millis(50)).await;

            // Old notarization must still be forwarded to voter.
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == target_view)
            );
        });
    }

    #[test_traced]
    fn test_old_notarization_after_nullification_is_forwarded() {
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        old_notarization_after_nullification_is_forwarded(bls12381_multisig::fixture::<MinPk, _>);
        old_notarization_after_nullification_is_forwarded(bls12381_multisig::fixture::<MinSig, _>);
        old_notarization_after_nullification_is_forwarded(ed25519::fixture);
        old_notarization_after_nullification_is_forwarded(secp256r1::fixture);
    }

    fn quorum_votes_construct_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Build proposal and votes
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send notarize votes from participants 1..quorum_size (excluding participant 0)
            // Participant 0's vote will be sent via mailbox.constructed()
            // Participant 1 is the leader, so their vote triggers proposal forwarding
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote via constructed message
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote))
                .await;

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(100)).await;

            // Should receive the leader's proposal first (participant 1 is leader)
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload"))
            );

            // Should receive notarization certificate from quorum of votes
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view));
        });
    }

    #[test_traced]
    fn test_quorum_votes_construct_certificate() {
        quorum_votes_construct_certificate(bls12381_threshold_vrf::fixture::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_threshold_vrf::fixture::<MinSig, _>);
        quorum_votes_construct_certificate(bls12381_threshold_std::fixture::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_threshold_std::fixture::<MinSig, _>);
        quorum_votes_construct_certificate(bls12381_multisig::fixture::<MinPk, _>);
        quorum_votes_construct_certificate(bls12381_multisig::fixture::<MinSig, _>);
        quorum_votes_construct_certificate(ed25519::fixture);
        quorum_votes_construct_certificate(secp256r1::fixture);
    }

    /// Test that if both votes and a certificate arrive, only one certificate is sent to voter.
    fn votes_and_certificate_deduplication<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Build proposal, votes, and certificate
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let notarization = build_notarization(&schemes, &proposal, quorum_size);

            // Send some votes (but not enough for quorum), starting with leader (participant 1)
            // This triggers proposal forwarding
            for i in 1..quorum_size - 1 {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote)).await;

            // Give network time to deliver votes
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal (participant 1)
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(&output, voter::Message::Proposal(p) if p.view() == view));

            // Now send the certificate from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Should receive exactly one notarization
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified(Certificate::Notarization(n), _) if n.view() == view)
            );

            // Now send enough votes to reach quorum (this vote would complete quorum)
            let last_vote =
                Notarize::sign(&schemes[quorum_size - 1], proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[quorum_size - 1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(last_vote).encode(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Try to receive another message (with timeout)
            let got_duplicate = select! {
                _ = voter_receiver.recv() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };

            // Should not receive another notarization since we already have one
            assert!(!got_duplicate, "Should not receive duplicate certificate");
        });
    }

    #[test_traced]
    fn test_votes_and_certificate_deduplication() {
        votes_and_certificate_deduplication(bls12381_threshold_vrf::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_threshold_vrf::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(bls12381_threshold_std::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_threshold_std::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(ed25519::fixture);
        votes_and_certificate_deduplication(secp256r1::fixture);
    }

    fn conflicting_votes_dont_produce_invalid_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 7;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Build TWO different proposals for the same view
            let round = Round::new(epoch, view);
            let proposal_a = Proposal::new(round, View::zero(), Sha256::hash(b"payload_a"));
            let proposal_b = Proposal::new(round, View::zero(), Sha256::hash(b"payload_b"));

            // Send vote for proposal_a from participant 1 (the leader)
            // This establishes proposal_a as the leader's proposal
            let leader_vote =
                Notarize::sign(&schemes[1], proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(leader_vote).encode(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give time for leader's vote to arrive and set leader_proposal
            context.sleep(Duration::from_millis(50)).await;

            // The batcher should receive the leader's proposal
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(
                &output,
                voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"payload_a")
            ));

            // Now send votes for proposal_b from participants 2, 3, 4, 5 (4 votes)
            // These are for a DIFFERENT proposal and should be filtered out by BatchVerifier
            for i in 2..=5 {
                let vote = Notarize::sign(&schemes[i], proposal_b.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
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
                _output = voter_receiver.recv() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };
            assert!(
                !got_certificate,
                "Should not have certificate - only 1 vote for leader's proposal"
            );

            // Now send 4 more votes for proposal_a (from participants 0,2,3,4)
            // Participant 0 is us, use constructed
            let our_vote = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote))
                .await;

            // Participants 6 hasn't voted yet - use them for proposal_a
            let vote6 = Notarize::sign(&schemes[6], proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[6] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(vote6).encode(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give time for processing
            context.sleep(Duration::from_millis(100)).await;

            // Still should not have certificate (only 3 votes for proposal_a: 0, 1, 6)
            let got_certificate = select! {
                _output = voter_receiver.recv() => { true },
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
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_votes_dont_produce_invalid_certificate(ed25519::fixture);
        conflicting_votes_dont_produce_invalid_certificate(secp256r1::fixture);
    }

    /// Test that when we receive a leader's notarize vote AFTER setting the leader,
    /// the proposal is forwarded to the voter (when we are not the leader).
    fn proposal_forwarded_after_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Give time for update to process
            context.sleep(Duration::from_millis(10)).await;

            // Build proposal and leader's vote
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], proposal.clone()).unwrap();

            // Now send the leader's vote - this should trigger proposal forwarding
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_after_leader_set() {
        proposal_forwarded_after_leader_set(bls12381_threshold_vrf::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_vrf::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_std::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_std::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(ed25519::fixture);
        proposal_forwarded_after_leader_set(secp256r1::fixture);
    }

    /// Test that when we receive a leader's notarize vote BEFORE setting the leader,
    /// the proposal is forwarded to the voter once the leader is set (when we are not the leader).
    fn proposal_forwarded_before_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader_vote = Notarize::sign(&schemes[1], proposal.clone()).unwrap();

            // Send the leader's vote BEFORE setting the leader
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Now set the leader - this should cause the proposal to be forwarded
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Give time for batcher to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal(p) if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set (vote arrived before leader was known)"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_before_leader_set() {
        proposal_forwarded_before_leader_set(bls12381_threshold_vrf::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_vrf::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_std::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_std::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(ed25519::fixture);
        proposal_forwarded_before_leader_set(secp256r1::fixture);
    }

    /// Test that leader activity detection works correctly:
    /// 1. Early views (before skip_timeout) always return active
    /// 2. With enough recent views, activity is determined by leader's votes
    /// 3. With gaps in recent views (with sufficient data), returns inactive
    fn leader_activity_detection<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
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
            let leader = Participant::new(1);
            for v in 1..skip_timeout {
                let view = View::new(v);
                let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
                assert!(nullify.is_none(), "view {v} should be active (before skip_timeout)");
            }

            // Test 2: At view skip_timeout, we now have skip_timeout entries (views 1-5)
            // and the leader hasn't voted, so they should be marked inactive
            let view = View::new(skip_timeout);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                nullify.is_some(),
                "view {skip_timeout} should be inactive (leader hasn't voted in {skip_timeout} views)"
            );

            // Test 3: Send a vote from the leader for the current view (view 5)
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], proposal).unwrap();
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                )
                .await
                .unwrap();

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Test 4: Advance to view skip_timeout + 1 (view 6)
            // Leader voted in view 5, which is in the recent window, so should be active
            let view = View::new(skip_timeout + 1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                nullify.is_none(),
                "view {} should be active (leader voted in view {})",
                skip_timeout + 1,
                skip_timeout
            );

            // Test 5: Jump far ahead to create a gap in recent views
            // Skip from view 6 to view 100 (this creates a gap where we don't have
            // data for views 7-99). The activity check looks at the last skip_timeout
            // rounds we have data for, so the leader's vote in view 5 is still visible.
            let view = View::new(100);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(
                nullify.is_none(),
                "view 100 should be active (leader voted in view 5, still in last {skip_timeout} rounds)"
            );
        });
    }

    #[test_traced]
    fn test_leader_activity_detection() {
        leader_activity_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_activity_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinSig, _>);
        leader_activity_detection(ed25519::fixture);
        leader_activity_detection(secp256r1::fixture);
    }

    /// Test that nullify-only participation marks a leader as active for skip-timeout
    /// heuristics.
    fn leader_nullify_marks_active<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_nullify_activity_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            let (voter_sender, _voter_receiver) =
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

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let leader = Participant::new(1);
            for v in 1..=skip_timeout {
                let view = View::new(v);
                let _ = batcher_mailbox.update(view, leader, View::zero()).await;
            }

            // Send a nullify vote from the leader in view skip_timeout.
            let round = Round::new(epoch, View::new(skip_timeout));
            let leader_vote = Nullify::sign::<Sha256Digest>(&schemes[1], round).unwrap();
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::<S, Sha256Digest>::Nullify(leader_vote).encode(),
                    true,
                )
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            // Nullify-only activity should still count as activity for skip-timeout.
            let next_view = View::new(skip_timeout + 1);
            let nullify = batcher_mailbox
                .update(next_view, leader, View::zero())
                .await;
            assert!(
                nullify.is_none(),
                "leader should remain active with nullify activity"
            );
        });
    }

    #[test_traced]
    fn test_leader_nullify_marks_active() {
        leader_nullify_marks_active(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_marks_active(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_marks_active(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_marks_active(ed25519::fixture);
        leader_nullify_marks_active(secp256r1::fixture);
    }

    /// Test that if a leader nullify for `v+1` is buffered while current view is `v`,
    /// entering `v+1` reports the leader inactive so the voter skips timeout immediately.
    fn leader_nullify_expire_on_view_entry<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_leader_nullify_expire_on_view_entry".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            let (voter_sender, _voter_receiver) =
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

            let leader_idx = Participant::new(2);
            let leader_pk = participants[usize::from(leader_idx)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    leader_pk.clone(),
                    me.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Enter view 1 first.
            let _ = batcher_mailbox
                .update(View::new(1), Participant::new(1), View::zero())
                .await;

            // Buffer a leader nullify for view 2 while current is still view 1.
            let buffered_view = View::new(2);
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::<S, Sha256Digest>::Nullify(
                        Nullify::sign::<Sha256Digest>(
                            &schemes[usize::from(leader_idx)],
                            Round::new(epoch, buffered_view),
                        )
                        .expect("nullify"),
                    )
                    .encode(),
                    true,
                )
                .await
                .unwrap();
            context.sleep(Duration::from_millis(50)).await;

            // Move current view to 2 with that same leader; this should fast-path timeout by
            // reporting the leader as inactive in the update response.
            let nullify = batcher_mailbox
                .update(buffered_view, leader_idx, View::zero())
                .await;
            assert!(
                nullify.is_some(),
                "buffered leader nullify should skip timeout on view entry"
            );
        });
    }

    #[test_traced]
    fn test_leader_nullify_expire_on_view_entry() {
        leader_nullify_expire_on_view_entry(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(ed25519::fixture);
        leader_nullify_expire_on_view_entry(secp256r1::fixture);
    }

    /// Test that we do not signal expiry when the sender is the current leader but the
    /// nullify vote is for a different view.
    fn leader_nullify_wrong_view_no_expire<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_leader_nullify_wrong_view_no_expire".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

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

            let leader = Participant::new(2);
            let leader_pk = participants[usize::from(leader)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    leader_pk,
                    me.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let current_view = View::new(2);
            let _ = batcher_mailbox
                .update(current_view, leader, View::zero())
                .await;

            let wrong_view = current_view.next();
            let leader_nullify = Nullify::sign::<Sha256Digest>(
                &schemes[usize::from(leader)],
                Round::new(epoch, wrong_view),
            )
            .expect("nullify");
            leader_sender
                .send(
                    Recipients::One(me),
                    Vote::<S, Sha256Digest>::Nullify(leader_nullify).encode(),
                    true,
                )
                .await
                .unwrap();

            let got_wrong_view_expire = select! {
                message = voter_receiver.recv() => {
                    matches!(message, Some(voter::Message::Nullify(view, _)) if view == wrong_view)
                },
                _ = context.sleep(Duration::from_millis(100)) => false,
            };
            assert!(
                !got_wrong_view_expire,
                "must not fast-path timeout for a leader nullify in a non-current view"
            );
        });
    }

    #[test_traced]
    fn test_leader_nullify_wrong_view_no_expire() {
        leader_nullify_wrong_view_no_expire(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(ed25519::fixture);
        leader_nullify_wrong_view_no_expire(secp256r1::fixture);
    }

    /// Test that votes above finalized trigger verification/construction,
    /// but votes at or below finalized do not.
    fn votes_skipped_for_finalized_views<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
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
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
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
            let leader = Participant::new(1);

            let nullify = batcher_mailbox.update(view1, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Part 1: Send NOTARIZE votes for view 1 (above finalized=0, should succeed)
            let round1 = Round::new(epoch, view1);
            let proposal1 = Proposal::new(round1, View::zero(), Sha256::hash(b"payload1"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal1.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own notarize vote for view 1 via constructed
            let our_notarize = Notarize::sign(&schemes[0], proposal1.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_notarize))
                .await;

            // Should receive a notarization certificate (view 1 is above finalized=0)
            loop {
                let output = voter_receiver.recv().await.unwrap();
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
            let nullify = batcher_mailbox.update(view3, leader, view2).await;
            assert!(nullify.is_none());

            // Send NOTARIZE votes for view 2 (now at finalized=2, should NOT succeed)
            let round2 = Round::new(epoch, view2);
            let proposal2 = Proposal::new(round2, view1, Sha256::hash(b"payload2"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal2.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own notarize vote for view 2 via constructed
            let our_notarize2 = Notarize::sign(&schemes[0], proposal2.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_notarize2))
                .await;

            // Should NOT receive any certificate for the finalized view
            select! {
                msg = voter_receiver.recv() => match msg {
                    Some(voter::Message::Proposal(_)) => {}
                    Some(voter::Message::Verified(cert, _)) if cert.view() == view2 => {
                        panic!("should not receive any certificate for the finalized view");
                    }
                    _ => {}
                },
                _ = context.sleep(Duration::from_millis(200)) => {},
            };
        });
    }

    #[test_traced]
    fn test_votes_skipped_for_finalized_views() {
        votes_skipped_for_finalized_views(bls12381_threshold_vrf::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_vrf::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_std::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_std::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(ed25519::fixture);
        votes_skipped_for_finalized_views(secp256r1::fixture);
    }

    fn latest_vote_metric_tracking<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
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
            } = fixture(&mut context, &namespace, n);

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_context = context.with_label("batcher");
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(batcher_context.clone(), batcher_cfg);

            // Verify all participants are initialized to view 0 in the metric
            let buffer = batcher_context.encode();
            for participant in &participants {
                let expected = format!("latest_vote{{peer=\"{}\"}} 0", participant);
                assert!(
                    buffer.contains(&expected),
                    "Expected metric for participant {} to be initialized to 0, got: {}",
                    participant,
                    buffer
                );
            }

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

            // Register participants on the network and set up links
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

            // Initialize batcher with view 5, participant 1 as leader
            let view = View::new(5);
            let leader = Participant::new(1);
            let nullify = batcher_mailbox.update(view, leader, View::zero()).await;
            assert!(nullify.is_none());

            // Build proposal and send enough votes to reach quorum
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send votes from participants 1 through quorum_size-1 (excluding 0, our own)
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        )
                        .await
                        .unwrap();
                }
            }

            // Send our own vote to complete the quorum
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote))
                .await;

            // Give network time to deliver and batcher time to process and construct certificate
            context.sleep(Duration::from_millis(100)).await;

            // Receive proposal and certificate
            loop {
                let output = voter_receiver.recv().await.unwrap();
                match output {
                    voter::Message::Proposal(_) => continue,
                    voter::Message::Verified(Certificate::Notarization(n), _) => {
                        assert_eq!(n.view(), view, "Should construct notarization");
                        break;
                    }
                    _ => panic!("Unexpected message type"),
                }
            }

            // Verify votes were tracked for participants who voted
            let buffer = batcher_context.encode();
            for (i, participant) in participants.iter().enumerate().take(quorum_size).skip(1) {
                let expected = format!("latest_vote{{peer=\"{}\"}} 5", participant);
                assert!(
                    buffer.contains(&expected),
                    "Expected participant {} to have latest_vote=5, got: {}",
                    i,
                    buffer
                );
            }

            // Now send a vote from a participant who hasn't voted yet (after quorum)
            // This tests that votes are still tracked even after certificate construction
            let late_voter = quorum_size;
            let late_vote = Notarize::sign(&schemes[late_voter], proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[late_voter] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(late_vote).encode(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(100)).await;

            // Verify the late vote was still tracked
            let buffer = batcher_context.encode();
            let expected_late = format!("latest_vote{{peer=\"{}\"}} 5", participants[late_voter]);
            assert!(
                buffer.contains(&expected_late),
                "Expected late voter (participant {}) to have latest_vote=5 even after quorum, got: {}",
                late_voter,
                buffer
            );

            // Send a vote for a LOWER view (view 3) from participant 1 who already voted at view 5
            // to verify the metric doesn't decrease
            let view3 = View::new(3);
            let round3 = Round::new(epoch, view3);
            let proposal3 = Proposal::new(round3, View::zero(), Sha256::hash(b"payload3"));
            let vote_v3 = Notarize::sign(&schemes[1], proposal3).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(vote_v3).encode(),
                        true,
                    )
                    .await
                    .unwrap();
            }

            context.sleep(Duration::from_millis(100)).await;

            // Verify participant 1 STILL has latest_vote = 5 (not decreased to 3)
            let buffer = batcher_context.encode();
            let expected_v5 = format!("latest_vote{{peer=\"{}\"}} 5", participants[1]);
            assert!(
                buffer.contains(&expected_v5),
                "Expected participant 1 to still have latest_vote=5 after receiving lower view vote, got: {}",
                buffer
            );
        });
    }

    #[test_traced]
    fn test_latest_vote_metric_tracking() {
        latest_vote_metric_tracking(bls12381_threshold_vrf::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_threshold_vrf::fixture::<MinSig, _>);
        latest_vote_metric_tracking(bls12381_threshold_std::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_threshold_std::fixture::<MinSig, _>);
        latest_vote_metric_tracking(bls12381_multisig::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_multisig::fixture::<MinSig, _>);
        latest_vote_metric_tracking(ed25519::fixture);
        latest_vote_metric_tracking(secp256r1::fixture);
    }

    fn duplicate_vote_with_different_attestation_blocks_peer<S, F, V>(mut fixture: F, sign_vote: V)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        V: Fn(&S, Proposal<Sha256Digest>) -> Vote<S, Sha256Digest> + Send + 'static,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            let (voter_sender, _voter_receiver) =
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

            // Set up participant 1 as sender
            let sender_pk = participants[1].clone();
            let (mut sender, _receiver) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            let nullify = batcher_mailbox
                .update(view, Participant::new(1), View::zero())
                .await;
            assert!(nullify.is_none());

            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send first valid vote from participant 1
            let vote1 = sign_vote(&schemes[1], proposal.clone());
            sender
                .send(Recipients::One(me.clone()), vote1.encode(), true)
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            // Verify not blocked yet
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "No peers should be blocked after first vote"
            );

            // Send same vote again (exact duplicate) - should be ignored, not blocked
            sender
                .send(Recipients::One(me.clone()), vote1.encode(), true)
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "Duplicate vote should be ignored, not blocked"
            );

            // Now send a vote with the SAME proposal but with a different signature
            let vote2 = sign_vote(&schemes[2], proposal.clone());
            sender
                .send(Recipients::One(me.clone()), vote2.encode(), true)
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            // Participant 1 should be blocked because they sent 2 votes with different attestations
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.iter().any(|(_, blocked)| blocked == &sender_pk),
                "Sender should be blocked for vote with mismatched signer"
            );
        });
    }

    fn sign_notarize<S: Scheme<Sha256Digest>>(
        scheme: &S,
        p: Proposal<Sha256Digest>,
    ) -> Vote<S, Sha256Digest> {
        Vote::Notarize(Notarize::sign(scheme, p).unwrap())
    }

    fn sign_finalize<S: Scheme<Sha256Digest>>(
        scheme: &S,
        p: Proposal<Sha256Digest>,
    ) -> Vote<S, Sha256Digest> {
        Vote::Finalize(Finalize::sign(scheme, p).unwrap())
    }

    #[test_traced]
    fn test_duplicate_notarize_with_different_attestation_blocks_peer() {
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(ed25519::fixture, sign_notarize);
        duplicate_vote_with_different_attestation_blocks_peer(secp256r1::fixture, sign_notarize);
    }

    #[test_traced]
    fn test_duplicate_finalize_with_different_attestation_blocks_peer() {
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(ed25519::fixture, sign_finalize);
        duplicate_vote_with_different_attestation_blocks_peer(secp256r1::fixture, sign_finalize);
    }

    fn conflicting_vote_creates_evidence<S, F, V, A>(
        mut fixture: F,
        sign_vote: V,
        is_expected_activity: A,
    ) where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        V: Fn(&S, Proposal<Sha256Digest>) -> Vote<S, Sha256Digest> + Send + 'static,
        A: Fn(&Activity<S, Sha256Digest>) -> bool + Send + 'static,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: 128,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.clone(), batcher_cfg);

            let (voter_sender, _voter_receiver) =
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

            // Set up participant 1 as sender
            let sender_pk = participants[1].clone();
            let (mut sender, _receiver) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            let nullify = batcher_mailbox
                .update(view, Participant::new(1), View::zero())
                .await;
            assert!(nullify.is_none());

            let round = Round::new(epoch, view);
            let proposal1 = Proposal::new(round, View::zero(), Sha256::hash(b"payload1"));
            let proposal2 = Proposal::new(round, View::zero(), Sha256::hash(b"payload2"));

            // Send first valid vote for proposal1
            let vote1 = sign_vote(&schemes[1], proposal1);
            sender
                .send(Recipients::One(me.clone()), vote1.encode(), true)
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "No peers should be blocked after first vote"
            );

            // Send conflicting vote for proposal2 (different payload = different proposal)
            let vote2 = sign_vote(&schemes[1], proposal2);
            sender
                .send(Recipients::One(me.clone()), vote2.encode(), true)
                .await
                .unwrap();

            context.sleep(Duration::from_millis(50)).await;

            // Participant 1 should be blocked for sending conflicting votes
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.iter().any(|(_, blocked)| blocked == &sender_pk),
                "Sender should be blocked for conflicting vote"
            );

            // Verify conflicting evidence was reported via faults
            let faults = reporter.faults.lock();
            let has_expected_fault = faults
                .get(&sender_pk)
                .and_then(|sf| sf.get(&view))
                .is_some_and(|vf| vf.iter().any(&is_expected_activity));
            assert!(has_expected_fault, "Should have conflicting fault reported");
        });
    }

    fn is_conflicting_notarize<S: Scheme<Sha256Digest>>(a: &Activity<S, Sha256Digest>) -> bool {
        matches!(a, Activity::ConflictingNotarize(_))
    }

    fn is_conflicting_finalize<S: Scheme<Sha256Digest>>(a: &Activity<S, Sha256Digest>) -> bool {
        matches!(a, Activity::ConflictingFinalize(_))
    }

    #[test_traced]
    fn test_conflicting_notarize_creates_evidence() {
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(ed25519::fixture, sign_notarize, is_conflicting_notarize);
        conflicting_vote_creates_evidence(
            secp256r1::fixture,
            sign_notarize,
            is_conflicting_notarize,
        );
    }

    #[test_traced]
    fn test_conflicting_finalize_creates_evidence() {
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(ed25519::fixture, sign_finalize, is_conflicting_finalize);
        conflicting_vote_creates_evidence(
            secp256r1::fixture,
            sign_finalize,
            is_conflicting_finalize,
        );
    }
}
