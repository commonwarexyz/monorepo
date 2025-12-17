mod actor;
mod ingress;
mod round;
mod slot;
mod state;

use crate::{
    simplex::types::Activity,
    types::{Epoch, ViewDelta},
    Automaton, Relay, Reporter,
};
pub use actor::Actor;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::PoolRef;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::Message;
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
    pub activity_timeout: ViewDelta,
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
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, Scheme},
            select_leader,
            types::{Certificate, Finalization, Finalize, Notarization, Notarize, Proposal, Vote},
        },
        types::{Round, View},
        Viewable,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config as NConfig, Network};
    use commonware_runtime::{deterministic, Clock, Metrics, Quota, Runner};
    use commonware_utils::{quorum, NZUsize};
    use futures::{channel::mpsc, FutureExt, StreamExt};
    use std::{num::NonZeroU32, sync::Arc, time::Duration};

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn build_notarization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Notarize<S, Sha256Digest>>,
        Notarization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let certificate = Notarization::from_notarizes(&schemes[0], &votes)
            .expect("notarization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_finalization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        namespace: &[u8],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Finalize<S, Sha256Digest>>,
        Finalization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
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
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
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

            // Initialize voter actor
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
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
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(5),
                activity_timeout: ViewDelta::new(10),
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

            // Create network senders for broadcasting votes and certificates
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Run the actor
            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for batcher to be notified
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    active,
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send finalization via voter mailbox (view 100)
            let payload = Sha256::hash(b"test");
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(100)),
                View::new(50),
                payload,
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

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
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
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
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization.view(), View::new(100));
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send old notarization from resolver that should be ignored (view 50)
            let payload = Sha256::hash(b"test2");
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(50)),
                View::new(49),
                payload,
            );
            let (_, notarization) = build_notarization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Send new finalization via voter mailbox (view 300)
            let payload = Sha256::hash(b"test3");
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(300)),
                View::new(100),
                payload,
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

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
                        assert_eq!(current, View::new(301));
                        assert_eq!(finalized, View::new(300));
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
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization.view(), View::new(300));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_stale_backfill() {
        stale_backfill(bls12381_threshold::fixture::<MinPk, _>);
        stale_backfill(bls12381_threshold::fixture::<MinSig, _>);
        stale_backfill(bls12381_multisig::fixture::<MinPk, _>);
        stale_backfill(bls12381_multisig::fixture::<MinSig, _>);
        stale_backfill(ed25519::fixture);
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
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"test_prune_panic".to_vec();
        let activity_timeout = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
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

            // Setup the target Voter actor (validator 0)
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
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
                epoch: Epoch::new(333),
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
            let (actor, mut mailbox) = Actor::new(context.clone(), voter_config);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(1);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(10);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Create network senders for broadcasting votes and certificates
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            actor.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Establish Prune Floor (50 - 10 + 5 = 45)
            //
            // Theoretical interesting floor is 50-10 = 40.
            // We want journal pruned at 45.
            let lf_target = View::new(50);
            let journal_floor_target = lf_target
                .saturating_sub(activity_timeout)
                .saturating_add(ViewDelta::new(5));

            // Send Finalization via voter mailbox to advance last_finalized
            let proposal_lf = Proposal::new(
                Round::new(Epoch::new(333), lf_target),
                lf_target.previous().unwrap(),
                Sha256::hash(b"test"),
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal_lf, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

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
                        assert_eq!(current, View::new(51));
                        assert_eq!(finalized, View::new(50));
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
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization.view(), View::new(50));
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send a Notarization for `journal_floor_target` to ensure it's in `actor.views`
            let proposal_jft = Proposal::new(
                Round::new(Epoch::new(333), journal_floor_target),
                journal_floor_target.previous().unwrap(),
                Sha256::hash(b"test2"),
            );
            let (_, notarization_for_floor) =
                build_notarization(&schemes, &namespace, &proposal_jft, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_for_floor))
                .await;

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                Certificate::Notarization(notarization) => {
                    assert_eq!(notarization.view(), journal_floor_target);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send notarization below oldest interesting view (42)
            //
            // problematic_view (42) < journal_floor_target (45)
            // interesting(42, false) -> 42 + AT(10) >= LF(50) -> 52 >= 50
            let problematic_view = journal_floor_target.saturating_sub(ViewDelta::new(3));
            let proposal_bft = Proposal::new(
                Round::new(Epoch::new(333), problematic_view),
                problematic_view.previous().unwrap(),
                Sha256::hash(b"test3"),
            );
            let (_, notarization_for_bft) =
                build_notarization(&schemes, &namespace, &proposal_bft, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_for_bft))
                .await;

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                Certificate::Notarization(notarization) => {
                    assert_eq!(notarization.view(), problematic_view);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send Finalization via voter mailbox to new view (100)
            let proposal_lf = Proposal::new(
                Round::new(Epoch::new(333), View::new(100)),
                View::new(99),
                Sha256::hash(b"test4"),
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal_lf, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

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
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
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
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization.view(), View::new(100));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_append_old_interesting_view() {
        append_old_interesting_view(bls12381_threshold::fixture::<MinPk, _>);
        append_old_interesting_view(bls12381_threshold::fixture::<MinSig, _>);
        append_old_interesting_view(bls12381_multisig::fixture::<MinPk, _>);
        append_old_interesting_view(bls12381_multisig::fixture::<MinSig, _>);
        append_old_interesting_view(ed25519::fixture);
    }

    /// Test that voter can process finalization from batcher without notarization.
    fn finalization_without_notarization_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
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
                participants: participants.clone().try_into().unwrap(),
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
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
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
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build a finalization certificate (without notarization)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"finalize_without_notarization"),
            );
            let (_, expected_finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox
                .recovered(Certificate::Finalization(expected_finalization.clone()))
                .await;

            // Wait for the actor to report the finalization
            let mut finalized_view = None;
            while let Some(message) = resolver_receiver.next().await {
                match message {
                    Certificate::Finalization(finalization) => {
                        finalized_view = Some(finalization.view());
                        break;
                    }
                    _ => continue,
                }
            }
            assert_eq!(finalized_view, Some(view));

            // Wait for a finalization to be recorded
            loop {
                {
                    let finalizations = reporter.finalizations.lock().unwrap();
                    // Finalization must match the signatures recovered from finalize votes
                    if matches!(
                        finalizations.get(&view),
                        Some(finalization) if finalization == &expected_finalization
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify no notarization certificate was recorded
            let notarizations = reporter.notarizations.lock().unwrap();
            assert!(notarizations.is_empty());
        });
    }

    #[test_traced]
    fn test_finalization_without_notarization_certificate() {
        finalization_without_notarization_certificate(bls12381_threshold::fixture::<MinPk, _>);
        finalization_without_notarization_certificate(bls12381_threshold::fixture::<MinSig, _>);
        finalization_without_notarization_certificate(bls12381_multisig::fixture::<MinPk, _>);
        finalization_without_notarization_certificate(bls12381_multisig::fixture::<MinSig, _>);
        finalization_without_notarization_certificate(ed25519::fixture);
    }

    fn certificate_conflicts_proposal<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
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
                participants: participants.clone().try_into().unwrap(),
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
                partition: "voter_certificate_conflicts_proposal_test".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
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

            // Register network channels
            let me = participants[0].clone();
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the voter
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    active,
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::zero());
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send proposal A from batcher (simulating leader's proposal being forwarded)
            let view = View::new(2);
            let proposal_a = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"proposal_a"),
            );
            mailbox.proposal(proposal_a.clone()).await;

            // Give it time to process the proposal
            context.sleep(Duration::from_millis(10)).await;

            // Send notarization certificate for a DIFFERENT proposal B
            let proposal_b = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"proposal_b"),
            );
            let (_, notarization_b) = build_notarization(&schemes, &namespace, &proposal_b, quorum);

            mailbox
                .recovered(Certificate::Notarization(notarization_b.clone()))
                .await;

            // Verify the certificate was accepted
            let msg = resolver_receiver
                .next()
                .await
                .expect("failed to receive resolver message");
            match msg {
                Certificate::Notarization(notarization) => {
                    assert_eq!(notarization.proposal, proposal_b);
                    assert_eq!(notarization, notarization_b);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization B to be recorded (not A)
            loop {
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
                    if matches!(
                        notarizations.get(&view),
                        Some(notarization) if notarization == &notarization_b
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Ensure no finalize vote is broadcast (don't vote on conflict)
            context.sleep(Duration::from_millis(100)).await;
            loop {
                let Some(Some(message)) = batcher_receiver.next().now_or_never() else {
                    break;
                };
                match message {
                    batcher::Message::Constructed(Vote::Finalize(_)) => {
                        panic!("finalize vote should not be broadcast");
                    }
                    batcher::Message::Update { active, .. } => {
                        active.send(true).unwrap();
                    }
                    _ => continue,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_conflicts_proposal() {
        certificate_conflicts_proposal(bls12381_threshold::fixture::<MinPk, _>);
        certificate_conflicts_proposal(bls12381_threshold::fixture::<MinSig, _>);
        certificate_conflicts_proposal(bls12381_multisig::fixture::<MinPk, _>);
        certificate_conflicts_proposal(bls12381_multisig::fixture::<MinSig, _>);
        certificate_conflicts_proposal(ed25519::fixture);
    }

    fn proposal_conflicts_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"proposal_conflicts_certificate_test".to_vec();
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
            } = fixture(&mut context, n);

            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
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

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_proposal_conflicts_certificate_test".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, mut resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let me = participants[0].clone();
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update { active, .. } => {
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            let view = View::new(2);
            let proposal_a = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"proposal_a"),
            );
            let proposal_b = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"proposal_b"),
            );

            // Send certificate for proposal A FIRST
            let (_, notarization_a) = build_notarization(&schemes, &namespace, &proposal_a, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_a.clone()))
                .await;

            // Verify the certificate was accepted
            let msg = resolver_receiver.next().await.unwrap();
            match msg {
                Certificate::Notarization(notarization) => {
                    assert_eq!(notarization.proposal, proposal_a);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization A to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
                    if matches!(
                        notarizations.get(&view),
                        Some(notarization) if notarization == &notarization_a
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Ensure finalize vote is sent
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(
                            finalize.proposal, proposal_a,
                            "finalize should be for certificate's proposal A"
                        );
                        break;
                    }
                    batcher::Message::Update { active, .. } => {
                        active.send(true).unwrap();
                    }
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }

            // Now send proposal B from batcher
            mailbox.proposal(proposal_b.clone()).await;

            // Wait for proposal B to be recorded (no issue)
            context.sleep(Duration::from_millis(100)).await;
        });
    }

    #[test_traced]
    fn test_proposal_conflicts_certificate() {
        proposal_conflicts_certificate(bls12381_threshold::fixture::<MinPk, _>);
        proposal_conflicts_certificate(bls12381_threshold::fixture::<MinSig, _>);
        proposal_conflicts_certificate(bls12381_multisig::fixture::<MinPk, _>);
        proposal_conflicts_certificate(bls12381_multisig::fixture::<MinSig, _>);
        proposal_conflicts_certificate(ed25519::fixture);
    }

    fn certificate_verifies_proposal<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
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
            } = fixture(&mut context, n);

            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
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
                verify_latency: (100_000.0, 0.0), // Very slow verification
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_certificate_conflicts_proposal_test".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, mut resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let me = participants[0].clone();
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update { active, .. } => {
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"same_proposal"),
            );

            // Send proposal from batcher first
            mailbox.proposal(proposal.clone()).await;

            // Give it time to start verification (but it won't complete due to slow latency)
            context.sleep(Duration::from_millis(10)).await;

            // Send certificate for the SAME proposal
            let (_, notarization) = build_notarization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization.clone()))
                .await;

            // The certificate should verify the proposal immediately
            let msg = resolver_receiver.next().await.unwrap();
            match msg {
                Certificate::Notarization(n) => {
                    assert_eq!(n.proposal, proposal);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
                    if matches!(
                        notarizations.get(&view),
                        Some(n) if n == &notarization
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Should be able to finalize since the proposal was verified by the certificate
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(finalize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Update { active, .. } => {
                        active.send(true).unwrap();
                    }
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_verifies_proposal() {
        certificate_verifies_proposal(bls12381_threshold::fixture::<MinPk, _>);
        certificate_verifies_proposal(bls12381_threshold::fixture::<MinSig, _>);
        certificate_verifies_proposal(bls12381_multisig::fixture::<MinPk, _>);
        certificate_verifies_proposal(bls12381_multisig::fixture::<MinSig, _>);
        certificate_verifies_proposal(ed25519::fixture);
    }

    /// Test that our proposal is dropped when it conflicts with a peer's notarize vote.
    ///
    /// This is a regression test for a byzantine scenario where multiple nodes share the
    /// same signing key:
    /// 1. A peer with our identity sends a notarize vote for proposal A
    /// 2. Our automaton completes with a different proposal B
    /// 3. Our proposal should be dropped when the conflict is detected
    fn drop_our_proposal_on_conflict<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey, Seed = ()>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"drop_our_proposal_on_conflict_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, oracle) = Network::new(
                context.with_label("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Get participants
            let Fixture {
                participants,
                schemes,
                verifier: _,
                ..
            } = fixture(&mut context, n);

            // Figure out who the leader will be for view 2
            let view2_round = Round::new(epoch, View::new(2));
            let (leader, leader_idx) = select_leader::<S>(&participants, view2_round, None);

            // Create a voter with the leader's identity
            let leader_scheme = schemes[leader_idx as usize].clone();

            // Setup application mock with some latency so we can inject peer
            // message before automaton completes
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: leader.clone(),
                propose_latency: (50.0, 10.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
                scheme: leader_scheme.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: leader_scheme.clone(),
                blocker: oracle.control(leader.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_leader".to_string(),
                epoch,
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
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

            // Register network channels
            let (vote_sender, _) = oracle
                .control(leader.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(leader.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the voter
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    active,
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Now create a finalization certificate for view 1 to advance to view 2
            let view1_round = Round::new(epoch, View::new(1));
            let view1_proposal =
                Proposal::new(view1_round, View::new(0), Sha256::hash(b"view1_payload"));

            let (_, finalization) =
                build_finalization(&schemes, &namespace, &view1_proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

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
                        assert_eq!(current, View::new(2));
                        assert_eq!(finalized, View::new(1));
                        active.send(true).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait a bit for the voter to request a proposal from automaton for view 2
            context.sleep(Duration::from_millis(5)).await;

            // Create a conflicting proposal from ourselves (equivocating) for view 2
            let conflicting_proposal =
                Proposal::new(view2_round, View::new(1), Sha256::hash(b"leader_proposal"));

            // Send the proposal via mailbox (simulating batcher receiving leader's notarize)
            // This happens AFTER we requested a proposal but BEFORE the automaton responds
            mailbox.proposal(conflicting_proposal.clone()).await;

            // Ensure we construct a notarize for our proposal
            while let Ok(Some(message)) = batcher_receiver.try_next() {
                match message {
                    batcher::Message::Constructed(Vote::Notarize(notarize)) => {
                        assert!(notarize.proposal == conflicting_proposal);
                    }
                    _ => panic!("unexpected batcher message"),
                }
            }

            // Now wait for our automaton to complete its proposal
            // This should trigger `our_proposal` which will see the conflicting proposal
            context.sleep(Duration::from_millis(100)).await;

            // Add a notarization certificate for conflicting proposal
            let (_, conflicting_notarization) =
                build_notarization(&schemes, &namespace, &conflicting_proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(conflicting_notarization.clone()))
                .await;

            // Wait for a finalize vote to be broadcast (we drop our own conflicting proposal rather than marking as replaced)
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(f)) => {
                        assert_eq!(f.proposal, conflicting_proposal);
                        break;
                    }
                    batcher::Message::Update { active, .. } => {
                        active.send(true).unwrap();
                    }
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test]
    fn test_drop_our_proposal_on_conflict() {
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinPk, _>);
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinSig, _>);
        drop_our_proposal_on_conflict(ed25519::fixture);
    }

    fn populate_resolver_on_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"populate_resolver_on_restart_test".to_vec();
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
                participants: participants.clone().try_into().unwrap(),
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
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
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
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            let handle = voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::zero());
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build finalization certificate for view 2
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"finalize_without_notarization"),
            );
            let (_, expected_finalization) =
                build_finalization(&schemes, &namespace, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox
                .recovered(Certificate::Finalization(expected_finalization.clone()))
                .await;

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.next().await.unwrap();
            match finalization {
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
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
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register new network channels for the validator (we don't use p2p, so this doesn't matter)
            let me = participants[0].clone();
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(3));
                    assert_eq!(finalized, View::new(2));
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.next().await.unwrap();
            match finalization {
                Certificate::Finalization(finalization) => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_populate_resolver_on_restart() {
        populate_resolver_on_restart(bls12381_threshold::fixture::<MinPk, _>);
        populate_resolver_on_restart(bls12381_threshold::fixture::<MinSig, _>);
        populate_resolver_on_restart(bls12381_multisig::fixture::<MinPk, _>);
        populate_resolver_on_restart(bls12381_multisig::fixture::<MinSig, _>);
        populate_resolver_on_restart(ed25519::fixture);
    }

    fn finalization_from_resolver<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // This is a regression test as the resolver didn't use to send
        // finalizations to the voter
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_from_resolver".to_vec();
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
                participants: participants.clone().try_into().unwrap(),
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
                partition: "finalization_from_resolver".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let me = participants[0].clone();
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::zero());
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send a finalization from resolver (view 2, which is current+1)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"finalization_from_resolver"),
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization.clone()))
                .await;

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update { finalized, .. } if finalized == view => break,
                    _ => continue,
                }
            }

            // Verify finalization was recorded by checking reporter
            let finalizations = reporter.finalizations.lock().unwrap();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
        });
    }

    #[test_traced]
    fn test_finalization_from_resolver() {
        finalization_from_resolver(bls12381_threshold::fixture::<MinPk, _>);
        finalization_from_resolver(bls12381_threshold::fixture::<MinSig, _>);
        finalization_from_resolver(bls12381_multisig::fixture::<MinPk, _>);
        finalization_from_resolver(bls12381_multisig::fixture::<MinSig, _>);
        finalization_from_resolver(ed25519::fixture);
    }

    /// Test that certificates received from the resolver are not sent back to it.
    ///
    /// This is a regression test for the "boomerang" bug where:
    /// 1. Resolver sends a certificate to the voter
    /// 2. Voter processes it and constructs the same certificate
    /// 3. Voter sends it back to resolver (unnecessary)
    fn no_resolver_boomerang<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_resolver_boomerang".to_vec();
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
                participants: participants.clone().try_into().unwrap(),
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
                partition: "no_resolver_boomerang".to_string(),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1000),
                nullify_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
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
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
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
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::zero());
                    active.send(true).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send a finalization from resolver (simulating resolver sending us a certificate)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(b"no_resolver_boomerang"),
            );
            let (_, finalization) = build_finalization(&schemes, &namespace, &proposal, quorum);
            mailbox
                .resolved(Certificate::Finalization(finalization.clone()))
                .await;

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.next().await.unwrap();
                match message {
                    batcher::Message::Update {
                        finalized, active, ..
                    } if finalized == view => {
                        active.send(true).unwrap();
                        break;
                    }
                    batcher::Message::Update { active, .. } => {
                        active.send(true).unwrap();
                    }
                    _ => continue,
                }
            }

            // Verify finalization was recorded
            let finalizations = reporter.finalizations.lock().unwrap();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
            drop(finalizations);

            // Ensure resolver hasn't been sent any messages (no boomerang)
            assert!(
                resolver_receiver.next().now_or_never().is_none(),
                "resolver should not receive the certificate back"
            );
        });
    }

    #[test_traced]
    fn test_no_resolver_boomerang() {
        no_resolver_boomerang(bls12381_threshold::fixture::<MinPk, _>);
        no_resolver_boomerang(bls12381_threshold::fixture::<MinSig, _>);
        no_resolver_boomerang(bls12381_multisig::fixture::<MinPk, _>);
        no_resolver_boomerang(bls12381_multisig::fixture::<MinSig, _>);
        no_resolver_boomerang(ed25519::fixture);
    }

    /// Tests that when proposal verification fails, the voter emits a nullify vote
    /// immediately rather than waiting for the timeout.
    fn verification_failure_emits_nullify_immediately<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let activity_timeout = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
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

            // Use participant[0] as the voter
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let reporter_cfg = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (10.0, 0.0), // 10ms verification latency
            };
            let (mut actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);

            // Configure application to always fail verification
            actor.set_fail_verification(true);
            actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_verify_fail_test_{me}"),
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                mailbox_size: 128,
                // Use long timeouts to prove nullify comes immediately, not from timeout
                leader_timeout: Duration::from_secs(10),
                notarization_timeout: Duration::from_secs(10),
                nullify_retry: Duration::from_secs(10),
                activity_timeout,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) = mpsc::channel(2);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(16);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let (vote_sender, _vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (certificate_sender, _certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher update
            let message = batcher_receiver.next().await.unwrap();
            match message {
                batcher::Message::Update { active, .. } => active.send(true).unwrap(),
                _ => panic!("expected Update message"),
            }

            // Advance views until we find one where we're NOT the leader (so we verify
            // rather than propose). Keep track of the previous view's proposal for parent.
            let mut current_view = View::new(1);
            let mut prev_proposal = Proposal::new(
                Round::new(Epoch::new(333), current_view),
                View::zero(),
                Sha256::hash(b"v0"),
            );

            let (target_view, leader) = loop {
                // Send finalization to advance to next view
                let (_, finalization) =
                    build_finalization(&schemes, &namespace, &prev_proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                // Wait for the view update
                let (new_view, leader) = loop {
                    match batcher_receiver.next().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            active,
                            ..
                        } => {
                            active.send(true).unwrap();
                            if current > current_view {
                                break (current, leader);
                            }
                        }
                        batcher::Message::Constructed(_) => {}
                    }
                };

                current_view = new_view;

                // Check if we're NOT the leader for this view
                if leader != 0 {
                    break (current_view, participants[leader as usize].clone());
                }

                // We're the leader, advance to next view
                prev_proposal = Proposal::new(
                    Round::new(Epoch::new(333), current_view),
                    current_view.previous().unwrap(),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
            };

            // Create proposal for the target view (where we are a verifier)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"test_proposal"),
            );

            // Broadcast the payload contents so verification can complete (the automaton waits
            // for the contents via the relay).
            let parent_payload = Sha256::hash(
                target_view
                    .previous()
                    .unwrap()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
            );
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay
                .broadcast(&leader, (proposal.payload, contents.into()))
                .await;
            mailbox.proposal(proposal).await;

            // Wait for nullify vote for target_view. Since timeouts are 10s, receiving it
            // within 1s proves it came from verification failure, not timeout.
            loop {
                select! {
                    msg = batcher_receiver.next() => {
                        match msg.unwrap() {
                            batcher::Message::Constructed(Vote::Nullify(nullify)) if nullify.view() == target_view => {
                                break;
                            }
                            batcher::Message::Update { active, .. } => active.send(true).unwrap(),
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("expected nullify for view {} within 1s (timeouts are 10s)", target_view);
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_failure_emits_nullify_immediately() {
        verification_failure_emits_nullify_immediately(bls12381_threshold::fixture::<MinPk, _>);
        verification_failure_emits_nullify_immediately(bls12381_threshold::fixture::<MinSig, _>);
        verification_failure_emits_nullify_immediately(bls12381_multisig::fixture::<MinPk, _>);
        verification_failure_emits_nullify_immediately(bls12381_multisig::fixture::<MinSig, _>);
        verification_failure_emits_nullify_immediately(ed25519::fixture);
    }
}
