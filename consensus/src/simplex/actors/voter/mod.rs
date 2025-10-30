mod actor;
mod ingress;

use crate::{
    simplex::{signing_scheme::Scheme, types::Activity},
    types::{Epoch, View},
    Automaton, Relay, Reporter,
};
pub use actor::Actor;
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_runtime::buffer::PoolRef;
pub use ingress::{Mailbox, Message};
use std::{num::NonZeroUsize, time::Duration};

pub struct Config<
    S: Scheme,
    B: Blocker,
    D: Digest,
    A: Automaton,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
> {
    pub scheme: S,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,

    pub partition: String,
    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub buffer_pool: PoolRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            actors::{batcher, resolver},
            mocks,
            mocks::fixtures::{bls12381_multisig, bls12381_threshold, ed25519, Fixture},
            types::{Finalization, Finalize, Notarization, Notarize, Proposal, Voter},
        },
        types::Round,
        Viewable,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        ed25519,
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network},
        Receiver, Recipients, Sender,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use commonware_utils::{quorum, NZUsize};
    use futures::{channel::mpsc, StreamExt};
    use std::{sync::Arc, time::Duration};

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn build_notarization<S: Scheme>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> (
        Vec<Notarize<S, Sha256Digest>>,
        Notarization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let certificate = Notarization::from_notarizes(&schemes[0], &votes)
            .expect("notarization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_finalization<S: Scheme>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> (
        Vec<Finalize<S, Sha256Digest>>,
        Finalization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Finalize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let certificate = Finalization::from_finalizes(&schemes[0], &votes)
            .expect("finalization requires a quorum of votes");
        (votes, certificate)
    }

    /// Trigger processing of an uninteresting view from the resolver after
    /// jumping ahead to a new finalize view:
    ///
    /// 1. Send a finalization for view 100.
    /// 2. Send a notarization from resolver for view 50 (should be ignored).
    /// 3. Send a finalization for view 300 (should be processed).
    fn stale_backfill<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
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

            // Initialize voter actor
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "test".to_string(),
                epoch: 333,
                namespace: namespace.clone(),
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(5),
                activity_timeout: 10,
                replay_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                write_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, mut mailbox) = Actor::new(context.clone(), cfg);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(1);
            let resolver = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(1024);
            let batcher = batcher::Mailbox::new(batcher_sender);

            // Create a dummy network mailbox
            let peer = participants[1].clone();
            let (pending_sender, _pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();
            let (mut _peer_pending_sender, mut _peer_pending_receiver) =
                oracle.control(peer.clone()).register(0).await.unwrap();
            let (mut peer_recovered_sender, mut peer_recovered_receiver) =
                oracle.control(peer.clone()).register(1).await.unwrap();
            oracle
                .add_link(
                    me.clone(),
                    peer.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    peer,
                    me,
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
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
            let payload = Sha256::hash(b"test");
            let proposal = Proposal::new(Round::new(333, 100), 50, payload);
            let (_, finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum as usize);
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
            let payload = Sha256::hash(b"test2");
            let proposal = Proposal::new(Round::new(333, 50), 49, payload);
            let (_, notarization) =
                build_notarization(&schemes, &namespace, &proposal, quorum as usize);
            mailbox
                .verified(vec![Voter::Notarization(notarization)])
                .await;

            // Send new finalization (view 300)
            let payload = Sha256::hash(b"test3");
            let proposal = Proposal::new(Round::new(333, 300), 100, payload);
            let (_, finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum as usize);
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

    #[test_traced]
    fn test_stale_backfill() {
        stale_backfill(bls12381_threshold::<MinPk, _>);
        stale_backfill(bls12381_threshold::<MinSig, _>);
        stale_backfill(bls12381_multisig::<MinPk, _>);
        stale_backfill(bls12381_multisig::<MinSig, _>);
        stale_backfill(ed25519);
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
    fn append_old_interesting_view<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"test_prune_panic".to_vec();
        let activity_timeout: View = 10;
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
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

            // Setup the target Voter actor (validator 0)
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: signing.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let app_config = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_config);
            actor.start();
            let voter_config = Config {
                scheme: signing.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_actor_test_{me}"),
                epoch: 333,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_millis(1000),
                nullify_retry: Duration::from_millis(1000),
                activity_timeout,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, _mailbox) = Actor::new(context.clone(), voter_config);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(1);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(10);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Create a dummy network mailbox
            let peer = participants[1].clone();
            let (pending_sender, _pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();
            let (mut _peer_pending_sender, mut _peer_pending_receiver) =
                oracle.control(peer.clone()).register(0).await.unwrap();
            let (mut peer_recovered_sender, mut peer_recovered_receiver) =
                oracle.control(peer.clone()).register(1).await.unwrap();
            oracle
                .add_link(
                    me.clone(),
                    peer.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    peer,
                    me,
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
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
            let proposal_lf = Proposal::new(
                Round::new(333, lf_target),
                lf_target - 1,
                Sha256::hash(b"test"),
            );
            let (_, finalization) =
                build_finalization(&schemes, &namespace, &proposal_lf, quorum as usize);
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
                Round::new(333, journal_floor_target),
                journal_floor_target - 1,
                Sha256::hash(b"test2"),
            );
            let (_, notarization_for_floor) =
                build_notarization(&schemes, &namespace, &proposal_jft, quorum as usize);
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
            let proposal_bft = Proposal::new(
                Round::new(333, problematic_view),
                problematic_view - 1,
                Sha256::hash(b"test3"),
            );
            let (_, notarization_for_bft) =
                build_notarization(&schemes, &namespace, &proposal_bft, quorum as usize);
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
            let proposal_lf = Proposal::new(Round::new(333, 100), 99, Sha256::hash(b"test4"));
            let (_, finalization) =
                build_finalization(&schemes, &namespace, &proposal_lf, quorum as usize);
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
        });
    }

    #[test_traced]
    fn test_append_old_interesting_view() {
        append_old_interesting_view(bls12381_threshold::<MinPk, _>);
        append_old_interesting_view(bls12381_threshold::<MinSig, _>);
        append_old_interesting_view(bls12381_multisig::<MinPk, _>);
        append_old_interesting_view(bls12381_multisig::<MinSig, _>);
        append_old_interesting_view(ed25519);
    }

    fn finalization_without_notarization_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_without_notarization".to_vec();
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
            } = fixture(&mut context, n);

            // Setup application mock
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_finalization_test".to_string(),
                epoch: 333,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: 10,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let me = participants[0].clone();
            let (pending_sender, _pending_receiver) =
                oracle.control(me.clone()).register(0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();

            // Start the actor
            voter.start(
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

            // Provide enough finalize votes without a notarization certificate
            let view = 2;
            let proposal = Proposal::new(
                Round::new(333, view),
                view - 1,
                Sha256::hash(b"finalize_without_notarization"),
            );
            let (finalize_votes, expected_finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum as usize);

            for finalize in finalize_votes.iter().cloned() {
                mailbox.verified(vec![Voter::Finalize(finalize)]).await;
            }

            // Wait for the actor to report the finalization
            let mut finalized_view = None;
            while let Some(message) = resolver_receiver.next().await {
                match message {
                    resolver::Message::Finalized { view: observed } => {
                        finalized_view = Some(observed);
                        break;
                    }
                    _ => continue,
                }
            }
            assert_eq!(finalized_view, Some(view));

            // Verify no notarization certificate was recorded
            let notarizations = reporter.notarizations.lock().unwrap();
            assert!(notarizations.is_empty());

            // Finalization must match the signatures recovered from finalize votes
            let finalizations = reporter.finalizations.lock().unwrap();
            let recorded = finalizations
                .get(&view)
                .expect("missing recorded finalization");
            assert_eq!(recorded, &expected_finalization);
        });
    }

    #[test_traced]
    fn test_finalization_without_notarization_certificate() {
        finalization_without_notarization_certificate(bls12381_threshold::<MinPk, _>);
        finalization_without_notarization_certificate(bls12381_threshold::<MinSig, _>);
        finalization_without_notarization_certificate(bls12381_multisig::<MinPk, _>);
        finalization_without_notarization_certificate(bls12381_multisig::<MinSig, _>);
        finalization_without_notarization_certificate(ed25519);
    }

    fn replay_duplicate_votes<S, F>(mut fixture: F)
    where
        S: Scheme<PublicKey = ed25519::PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_without_notarization".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None
                },
            );
            network.start();

            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);

            // Setup application mock
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().into(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_finalization_test".to_string(),
                epoch: 333,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: 10,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let me = participants[0].clone();
            let (pending_sender, _pending_receiver) = oracle.control(me.clone()).register(0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(1).await.unwrap();

            // Start the actor
            let handle = voter.start(
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

            // Provide almost enough finalize votes
            let view = 2;
            let proposal = Proposal::new(
                Round::new(333, view),
                view - 1,
                Sha256::hash(b"finalize_without_notarization"),
            );
            let (notarize_votes, expected_notarization) =
                build_notarization(&schemes, &namespace, &proposal, quorum as usize);
            let (finalize_votes, expected_finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum as usize);

            // Submit just short of enough finalize votes
            for finalize in finalize_votes.iter().take(quorum as usize - 1).cloned() {
                mailbox.verified(vec![Voter::Finalize(finalize)]).await;
            }

            // Submit enough notarize votes to broadcast and force a sync
            for notarize in notarize_votes.iter().take(quorum as usize).cloned() {
                mailbox.verified(vec![Voter::Notarize(notarize)]).await;
            }

            // Wait for a notarization to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
                    if matches!(notarizations.get(&view), Some(expected) if expected == &expected_notarization) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Restart voter
            handle.abort();

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_finalization_test".to_string(),
                epoch: 333,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: 10,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register new network channels for the validator (we don't use p2p, so this doesn't matter)
            let me = participants[0].clone();
            let (pending_sender, _pending_receiver) = oracle.control(me.clone()).register(2).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.control(me.clone()).register(3).await.unwrap();

            // Start the actor
            voter.start(
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
                    assert_eq!(current, 3);
                    assert_eq!(finalized, 0);
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Provide duplicate finalize votes (should be ignored)
            for finalize in finalize_votes.iter().take(quorum as usize - 1).cloned() {
                mailbox.verified(vec![Voter::Finalize(finalize)]).await;
            }

            // Verify no finalization was recorded
            context.sleep(Duration::from_secs(1)).await;
            {
                let finalizations = reporter.finalizations.lock().unwrap();
                assert!(finalizations.is_empty());
            }

            // Provide the final finalize vote
            mailbox
                .verified(vec![Voter::Finalize(
                    finalize_votes.last().unwrap().clone(),
                )])
                .await;

            // Verify the finalization was recorded
            loop {
                {
                    let finalizations = reporter.finalizations.lock().unwrap();
                    if matches!(finalizations.get(&view), Some(expected) if expected == &expected_finalization) {
                        // The reporter already checks the certificate for signature validity, so we don't need to do it here.
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }
        });
    }

    #[test_traced]
    fn test_replay_duplicate_votes() {
        replay_duplicate_votes(bls12381_threshold::<MinPk, _>);
        replay_duplicate_votes(bls12381_threshold::<MinSig, _>);
        replay_duplicate_votes(bls12381_multisig::<MinPk, _>);
        replay_duplicate_votes(bls12381_multisig::<MinSig, _>);
        replay_duplicate_votes(ed25519);
    }
}
