mod actor;
mod ingress;
mod round;
mod slot;
mod state;

use crate::{
    simplex::{elector::Config as Elector, types::Activity, Plan},
    types::{Epoch, ViewDelta},
    CertifiableAutomaton, Relay, Reporter,
};
pub use actor::Actor;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::paged::CacheRef;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::Message;
use std::{num::NonZeroUsize, time::Duration};

pub struct Config<
    S: Scheme,
    L: Elector<S>,
    B: Blocker,
    D: Digest,
    A: CertifiableAutomaton,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = Activity<S, D>>,
> {
    pub scheme: S,
    pub elector: L,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,

    pub partition: String,
    pub epoch: Epoch,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub activity_timeout: ViewDelta,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub page_cache: CacheRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            actors::{
                batcher,
                resolver::{self, MailboxMessage},
            },
            elector::{Config as ElectorConfig, Elector, Random, RoundRobin, RoundRobinElector},
            metrics::TimeoutReason,
            mocks, quorum,
            scheme::{
                bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519,
                secp256r1, Scheme,
            },
            types::{
                Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
                Nullify, Proposal, Vote,
            },
        },
        types::{Participant, Round, View},
        Viewable,
    };
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256,
    };
    use commonware_macros::{select, test_collect_traces, test_traced};
    use commonware_p2p::simulated::{Config as NConfig, Link, Network, Oracle};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        deterministic, telemetry::traces::collector::TraceStorage, Clock, Metrics, Quota, Runner,
    };
    use commonware_utils::{channel::mpsc, sync::Mutex, NZUsize, NZU16};
    use futures::FutureExt;
    use std::{
        num::{NonZeroU16, NonZeroU32},
        sync::Arc,
        time::Duration,
    };
    use tracing::Level;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    async fn start_test_network_with_peers<I>(
        context: deterministic::Context,
        peers: I,
        disconnect_on_block: bool,
    ) -> Oracle<PublicKey, deterministic::Context>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let (network, oracle) = Network::new_with_peers(
            context.with_label("network"),
            NConfig {
                max_size: 1024 * 1024,
                disconnect_on_block,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        oracle
    }

    fn build_notarization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Notarize<S, Sha256Digest>>,
        Notarization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate = Notarization::from_notarizes(&schemes[0], &votes, &Sequential)
            .expect("notarization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_finalization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Finalize<S, Sha256Digest>>,
        Finalization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate = Finalization::from_finalizes(&schemes[0], &votes, &Sequential)
            .expect("finalization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_nullification<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        round: Round,
        count: u32,
    ) -> (Vec<Nullify<S>>, Nullification<S>) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        let certificate = Nullification::from_nullifies(&schemes[0], &votes, &Sequential)
            .expect("nullification requires a quorum of votes");
        (votes, certificate)
    }

    /// Helper to set up a voter actor for tests.
    #[allow(clippy::too_many_arguments)]
    async fn setup_voter<S, L>(
        context: &mut deterministic::Context,
        oracle: &commonware_p2p::simulated::Oracle<S::PublicKey, deterministic::Context>,
        participants: &[S::PublicKey],
        schemes: &[S],
        elector: L,
        leader_timeout: Duration,
        certification_timeout: Duration,
        timeout_retry: Duration,
        should_certify: mocks::application::Certifier<Sha256Digest>,
    ) -> (
        Mailbox<S, Sha256Digest>,
        mpsc::Receiver<batcher::Message<S, Sha256Digest>>,
        mpsc::Receiver<resolver::MailboxMessage<S, Sha256Digest>>,
        Arc<mocks::relay::Relay<Sha256Digest, S::PublicKey>>,
        mocks::reporter::Reporter<deterministic::Context, S, L, Sha256Digest>,
    )
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        L: ElectorConfig<S>,
    {
        let signing = schemes[0].clone();
        let me = participants[0].clone();
        let reporter_cfg = mocks::reporter::Config {
            participants: participants.to_vec().try_into().unwrap(),
            scheme: signing.clone(),
            elector: elector.clone(),
        };
        let reporter = mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
        let relay = Arc::new(mocks::relay::Relay::new());

        let application_cfg = mocks::application::Config {
            hasher: Sha256::default(),
            relay: relay.clone(),
            me: me.clone(),
            propose_latency: (1.0, 0.0),
            verify_latency: (1.0, 0.0),
            certify_latency: (1.0, 0.0),
            should_certify,
        };
        let (actor, application) =
            mocks::application::Application::new(context.with_label("app"), application_cfg);
        actor.start();

        let page_cache =
            CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
        let voter_cfg = Config {
            scheme: signing.clone(),
            elector,
            blocker: oracle.control(me.clone()),
            automaton: application.clone(),
            relay: application.clone(),
            reporter: reporter.clone(),
            partition: format!("voter_test_{me}"),
            epoch: Epoch::new(333),
            mailbox_size: 128,
            leader_timeout,
            certification_timeout,
            timeout_retry,
            activity_timeout: ViewDelta::new(10),
            replay_buffer: NZUsize!(10240),
            write_buffer: NZUsize!(10240),
            page_cache,
        };
        let (voter, mailbox) = Actor::new(context.clone(), voter_cfg);

        let (resolver_sender, resolver_receiver) = mpsc::channel(8);
        let (batcher_sender, batcher_receiver) = mpsc::channel(16);

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
            batcher::Mailbox::new(batcher_sender),
            resolver::Mailbox::new(resolver_sender),
            vote_sender,
            certificate_sender,
        );

        (
            mailbox,
            batcher_receiver,
            resolver_receiver,
            relay,
            reporter,
        )
    }

    /// Helper to advance to a specific view by sending a finalization for the previous view.
    async fn advance_to_view<S: Scheme<Sha256Digest>>(
        mailbox: &mut Mailbox<S, Sha256Digest>,
        batcher_receiver: &mut mpsc::Receiver<batcher::Message<S, Sha256Digest>>,
        schemes: &[S],
        quorum: u32,
        target: View,
    ) -> Sha256Digest {
        let prev_view = target.previous().expect("target view must be > 0");
        let payload = Sha256::hash(prev_view.get().to_be_bytes().as_slice());
        let proposal = Proposal::new(
            Round::new(Epoch::new(333), prev_view),
            prev_view.previous().unwrap_or(View::zero()),
            payload,
        );
        let (_, finalization) = build_finalization(schemes, &proposal, quorum);
        mailbox
            .resolved(Certificate::Finalization(finalization))
            .await;

        // Wait for target view update
        loop {
            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update {
                    current, response, ..
                } => {
                    response.send(None).unwrap();
                    if current < target {
                        continue;
                    }
                    assert_eq!(current, target);
                    break;
                }
                batcher::Message::Constructed(_) => {}
            }
        }

        payload
    }

    /// Trigger processing of an uninteresting view from the resolver after
    /// jumping ahead to a new finalize view:
    ///
    /// 1. Send a finalization for view 100.
    /// 2. Send a notarization from resolver for view 50 (should be ignored).
    /// 3. Send a finalization for view 300 (should be processed).
    fn stale_backfill<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), false).await;

            // Initialize voter actor
            let me = participants[0].clone();
            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
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
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Sometimes,
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 10,
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                write_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                page_cache,
            };
            let (actor, mut mailbox) = Actor::new(context.with_label("voter"), cfg);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(10);
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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        response,
                        ..
                    } => {
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
                        response.send(None).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
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
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
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
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        response,
                        ..
                    } => {
                        assert_eq!(current, View::new(301));
                        assert_eq!(finalized, View::new(300));
                        response.send(None).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
                    assert_eq!(finalization.view(), View::new(300));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_stale_backfill() {
        stale_backfill::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        stale_backfill::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        stale_backfill::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        stale_backfill::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        stale_backfill::<_, _, RoundRobin>(ed25519::fixture);
        stale_backfill::<_, _, RoundRobin>(secp256r1::fixture);
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
    fn append_old_interesting_view<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"test_prune_panic".to_vec();
        let activity_timeout = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup the target Voter actor (validator 0)
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
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
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Sometimes,
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_config);
            actor.start();
            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_config = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_actor_test_{me}"),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_millis(1000),
                timeout_retry: Duration::from_millis(1000),
                activity_timeout,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (actor, mut mailbox) = Actor::new(context.clone(), voter_config);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) = mpsc::channel(10);
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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, finalization) = build_finalization(&schemes, &proposal_lf, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        response,
                        ..
                    } => {
                        assert_eq!(current, View::new(51));
                        assert_eq!(finalized, View::new(50));
                        response.send(None).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
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
            let (_, notarization_for_floor) = build_notarization(&schemes, &proposal_jft, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_for_floor))
                .await;

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Notarization(notarization)) => {
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
            let (_, notarization_for_bft) = build_notarization(&schemes, &proposal_bft, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_for_bft))
                .await;

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Notarization(notarization)) => {
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
            let (_, finalization) = build_finalization(&schemes, &proposal_lf, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        response,
                        ..
                    } => {
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
                        response.send(None).unwrap();
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
                    assert_eq!(finalization.view(), View::new(100));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_append_old_interesting_view() {
        append_old_interesting_view::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        append_old_interesting_view::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        append_old_interesting_view::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        append_old_interesting_view::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        append_old_interesting_view::<_, _, RoundRobin>(ed25519::fixture);
        append_old_interesting_view::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Test that voter can process finalization from batcher without notarization.
    fn finalization_without_notarization_certificate<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_without_notarization".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = L::default();
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    Duration::from_millis(500),
                    Duration::from_secs(1000),
                    Duration::from_secs(1000),
                    mocks::application::Certifier::Sometimes,
                )
                .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, expected_finalization) = build_finalization(&schemes, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox
                .recovered(Certificate::Finalization(expected_finalization.clone()))
                .await;

            // Wait for the actor to report the finalization
            let mut finalized_view = None;
            while let Some(message) = resolver_receiver.recv().await {
                match message {
                    MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
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
                    let finalizations = reporter.finalizations.lock();
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
            let notarizations = reporter.notarizations.lock();
            assert!(notarizations.is_empty());
        });
    }

    #[test_traced]
    fn test_finalization_without_notarization_certificate() {
        finalization_without_notarization_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        finalization_without_notarization_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(ed25519::fixture);
        finalization_without_notarization_certificate::<_, _, RoundRobin>(secp256r1::fixture);
    }

    fn certificate_conflicts_proposal<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = L::default();
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    Duration::from_millis(500),
                    Duration::from_secs(1000),
                    Duration::from_secs(1000),
                    mocks::application::Certifier::Sometimes,
                )
                .await;

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, notarization_b) = build_notarization(&schemes, &proposal_b, quorum);

            mailbox
                .recovered(Certificate::Notarization(notarization_b.clone()))
                .await;

            // Verify the certificate was accepted
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate(Certificate::Notarization(notarization)) => {
                    assert_eq!(notarization.proposal, proposal_b);
                    assert_eq!(notarization, notarization_b);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization B to be recorded (not A)
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
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
                let Some(Some(message)) = batcher_receiver.recv().now_or_never() else {
                    break;
                };
                match message {
                    batcher::Message::Constructed(Vote::Finalize(_)) => {
                        panic!("finalize vote should not be broadcast");
                    }
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                    }
                    _ => continue,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_conflicts_proposal() {
        certificate_conflicts_proposal::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certificate_conflicts_proposal::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certificate_conflicts_proposal::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        certificate_conflicts_proposal::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        certificate_conflicts_proposal::<_, _, RoundRobin>(ed25519::fixture);
        certificate_conflicts_proposal::<_, _, RoundRobin>(secp256r1::fixture);
    }

    fn proposal_conflicts_certificate<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"proposal_conflicts_certificate_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = L::default();
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    Duration::from_millis(500),
                    Duration::from_secs(1000),
                    Duration::from_secs(1000),
                    mocks::application::Certifier::Sometimes,
                )
                .await;

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { response, .. } => {
                    response.send(None).unwrap();
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
            let (_, notarization_a) = build_notarization(&schemes, &proposal_a, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization_a.clone()))
                .await;

            // Verify the certificate was accepted
            let msg = resolver_receiver.recv().await.unwrap();
            match msg {
                MailboxMessage::Certificate(Certificate::Notarization(notarization)) => {
                    assert_eq!(notarization.proposal, proposal_a);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization A to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
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
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(
                            finalize.proposal, proposal_a,
                            "finalize should be for certificate's proposal A"
                        );
                        break;
                    }
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
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
        proposal_conflicts_certificate::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        proposal_conflicts_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        proposal_conflicts_certificate::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        proposal_conflicts_certificate::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        proposal_conflicts_certificate::<_, _, RoundRobin>(ed25519::fixture);
        proposal_conflicts_certificate::<_, _, RoundRobin>(secp256r1::fixture);
    }

    fn certificate_verifies_proposal<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
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
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Sometimes,
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_certificate_verifies_proposal_test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { response, .. } => {
                    response.send(None).unwrap();
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
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization.clone()))
                .await;

            // The certificate should verify the proposal immediately
            let msg = resolver_receiver.recv().await.unwrap();
            match msg {
                MailboxMessage::Certificate(Certificate::Notarization(n)) => {
                    assert_eq!(n.proposal, proposal);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
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
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(finalize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                    }
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_verifies_proposal() {
        certificate_verifies_proposal::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certificate_verifies_proposal::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certificate_verifies_proposal::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        certificate_verifies_proposal::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        certificate_verifies_proposal::<_, _, RoundRobin>(ed25519::fixture);
        certificate_verifies_proposal::<_, _, RoundRobin>(secp256r1::fixture);
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
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"drop_our_proposal_on_conflict_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                verifier: _,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Figure out who the leader will be for view 2
            let view2_round = Round::new(epoch, View::new(2));
            let elector_config = RoundRobin::<Sha256>::default();
            let temp_elector: RoundRobinElector<S> =
                elector_config.clone().build(schemes[0].participants());
            let leader_idx = temp_elector.elect(view2_round, None);
            let leader = participants[usize::from(leader_idx)].clone();

            // Create a voter with the leader's identity
            let leader_scheme = schemes[usize::from(leader_idx)].clone();

            // Setup application mock with some latency so we can inject peer
            // message before automaton completes
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: leader.clone(),
                propose_latency: (50.0, 10.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: leader_scheme.clone(),
                elector: elector_config.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

            // Initialize voter actor
            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: leader_scheme.clone(),
                elector: elector_config,
                blocker: oracle.control(leader.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_leader".to_string(),
                epoch,
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Now create a finalization certificate for view 1 to advance to view 2
            let view1_round = Round::new(epoch, View::new(1));
            let view1_proposal =
                Proposal::new(view1_round, View::new(0), Sha256::hash(b"view1_payload"));

            let (_, finalization) = build_finalization(&schemes, &view1_proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        response,
                        ..
                    } => {
                        assert_eq!(current, View::new(2));
                        assert_eq!(finalized, View::new(1));
                        response.send(None).unwrap();
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
            while let Ok(message) = batcher_receiver.try_recv() {
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
                build_notarization(&schemes, &conflicting_proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(conflicting_notarization.clone()))
                .await;

            // Wait for a finalize vote to be broadcast (we drop our own conflicting proposal rather than marking as replaced)
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(f)) => {
                        assert_eq!(f.proposal, conflicting_proposal);
                        break;
                    }
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                    }
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test_traced]
    fn test_drop_our_proposal_on_conflict() {
        drop_our_proposal_on_conflict(bls12381_threshold_vrf::fixture::<MinPk, _>);
        drop_our_proposal_on_conflict(bls12381_threshold_vrf::fixture::<MinSig, _>);
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinPk, _>);
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinSig, _>);
        drop_our_proposal_on_conflict(ed25519::fixture);
        drop_our_proposal_on_conflict(secp256r1::fixture);
    }

    fn populate_resolver_on_restart<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"populate_resolver_on_restart_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock
            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
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
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Sometimes,
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            actor.start();

            // Initialize voter actor
            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter"), voter_cfg);

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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, expected_finalization) = build_finalization(&schemes, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox
                .recovered(Certificate::Finalization(expected_finalization.clone()))
                .await;

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.recv().await.unwrap();
            match finalization {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Restart voter
            handle.abort();

            // Initialize voter actor
            let page_cache = CacheRef::from_pooler(
                context.with_label("cache_restarted"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, _mailbox) = Actor::new(context.with_label("voter_restarted"), voter_cfg);

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
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(3));
                    assert_eq!(finalized, View::new(2));
                    response.send(None).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.recv().await.unwrap();
            match finalization {
                MailboxMessage::Certificate(Certificate::Finalization(finalization)) => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_populate_resolver_on_restart() {
        populate_resolver_on_restart::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        populate_resolver_on_restart::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        populate_resolver_on_restart::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        populate_resolver_on_restart::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        populate_resolver_on_restart::<_, _, RoundRobin>(ed25519::fixture);
        populate_resolver_on_restart::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Regression: startup must consume timeout hints returned by initial batcher update.
    ///
    /// On restart, we recover into `target_view` and inject `LeaderNullify` from the
    /// first `batcher.update`. Even with long timeouts, voter must emit `nullify(target_view)`
    /// immediately rather than waiting for `leader_timeout`.
    fn startup_update_timeout_hint_nullifies_recovered_view<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"startup_update_timeout_hint_nullify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;
            let me = participants[0].clone();

            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor.start();

            let partition = "voter_startup_update_timeout_hint_nullify".to_string();
            let epoch = Epoch::new(333);
            let make_cfg = |page_cache: CacheRef| Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                mailbox_size: 128,
                // Long deadlines prove nullify comes from startup timeout hint, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };

            // First run: persist progress to a later view.
            let cfg = make_cfg(CacheRef::from_pooler(
                context.with_label("cache_initial"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            ));
            let (voter, mut mailbox) = Actor::new(context.with_label("voter_initial"), cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(32);
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
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                certificate_sender,
            );

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                _ => panic!("expected initial update"),
            }

            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            handle.abort();

            // Restart and inject startup timeout hint from first update.
            let cfg = make_cfg(CacheRef::from_pooler(
                context.with_label("cache_restarted"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            ));
            let (voter, _mailbox) = Actor::new(context.with_label("voter_restarted"), cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(32);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                certificate_sender,
            );

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update {
                    current,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, target_view);
                    assert_eq!(finalized, target_view.previous().unwrap());
                    response.send(Some(TimeoutReason::LeaderNullify)).unwrap();
                }
                _ => panic!("expected startup update after restart"),
            }

            // Expect immediate nullify from startup timeout hint despite 10s timeouts.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected immediate nullify for recovered view {target_view} from startup timeout hint"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_startup_update_timeout_hint_nullifies_recovered_view() {
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(ed25519::fixture);
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(secp256r1::fixture);
    }

    fn finalization_from_resolver<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // This is a regression test as the resolver didn't use to send
        // finalizations to the voter
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_from_resolver".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = L::default();
            let (mut mailbox, mut batcher_receiver, _, _, reporter) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_millis(500),
                Duration::from_secs(1000),
                Duration::from_secs(1000),
                mocks::application::Certifier::Sometimes,
            )
            .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization.clone()))
                .await;

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update { finalized, .. } if finalized == view => break,
                    _ => continue,
                }
            }

            // Verify finalization was recorded by checking reporter
            let finalizations = reporter.finalizations.lock();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
        });
    }

    #[test_traced]
    fn test_finalization_from_resolver() {
        finalization_from_resolver::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalization_from_resolver::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalization_from_resolver::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        finalization_from_resolver::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        finalization_from_resolver::<_, _, RoundRobin>(ed25519::fixture);
        finalization_from_resolver::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Test that certificates received from the resolver are not sent back to it.
    ///
    /// This is a regression test for the "boomerang" bug where:
    /// 1. Resolver sends a certificate to the voter
    /// 2. Voter processes it and constructs the same certificate
    /// 3. Voter sends it back to resolver (unnecessary)
    fn no_resolver_boomerang<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_resolver_boomerang".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = L::default();
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    Duration::from_millis(500),
                    Duration::from_secs(1000),
                    Duration::from_secs(1000),
                    mocks::application::Certifier::Sometimes,
                )
                .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
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
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Finalization(finalization.clone()))
                .await;

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        finalized,
                        response,
                        ..
                    } if finalized == view => {
                        response.send(None).unwrap();
                        break;
                    }
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                    }
                    _ => continue,
                }
            }

            // Verify finalization was recorded
            let finalizations = reporter.finalizations.lock();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
            drop(finalizations);

            // Ensure resolver hasn't been sent any messages (no boomerang)
            assert!(
                resolver_receiver.recv().now_or_never().is_none(),
                "resolver should not receive the certificate back"
            );
        });
    }

    #[test_traced]
    fn test_no_resolver_boomerang() {
        no_resolver_boomerang::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_resolver_boomerang::<_, _, Random>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_resolver_boomerang::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        no_resolver_boomerang::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinSig, _>);
        no_resolver_boomerang::<_, _, RoundRobin>(ed25519::fixture);
        no_resolver_boomerang::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Tests that when proposal verification fails, the voter emits a nullify vote
    /// immediately rather than waiting for the timeout.
    fn verification_failure_emits_nullify_immediately<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let activity_timeout = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Use participant[0] as the voter
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
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
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);

            // Configure application to always fail verification
            actor.set_fail_verification(true);
            actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_verify_fail_test_{me}"),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                // Use long timeouts to prove nullify comes immediately, not from timeout
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                activity_timeout,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) = mpsc::channel(2);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(16);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
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

            // Wait for initial batcher update
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { response, .. } => response.send(None).unwrap(),
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
                let (_, finalization) = build_finalization(&schemes, &prev_proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                // Wait for the view update
                let (new_view, leader) = loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } => {
                            response.send(None).unwrap();
                            if current > current_view {
                                break (current, leader);
                            }
                        }
                        batcher::Message::Constructed(_) => {}
                    }
                };

                current_view = new_view;

                // Check if we're NOT the leader for this view
                if leader != Participant::new(0) {
                    break (current_view, participants[usize::from(leader)].clone());
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
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal).await;

            // Wait for nullify vote for target_view. Since timeouts are 10s, receiving it
            // within 1s proves it came from verification failure, not timeout.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_failure_emits_nullify_immediately() {
        verification_failure_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        verification_failure_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(ed25519::fixture);
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Tests that observing a leader's `nullify` vote fast-paths timeout for verifiers.
    fn leader_nullify_fast_paths_timeout<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"leader_nullify_fast_paths_timeout".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_leader_nullify_fast_path_{me}"),
                epoch,
                mailbox_size: 128,
                // Long timeouts prove nullify came from fast-path, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(32);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

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

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        (current, leader)
                    }
                    _ => panic!("expected initial update"),
                };

            // Move to a non-leader view so we act as a verifier.
            while current_leader == me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } if current > current_view => {
                            response.send(None).unwrap();
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            let target_view = current_view;
            mailbox
                .timeout(target_view, TimeoutReason::LeaderNullify)
                .await;

            // Expect local nullify quickly despite 10s timeouts.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Send the same expire signal again. Duplicates should not retrigger the fast-path.
            mailbox
                .timeout(target_view, TimeoutReason::LeaderNullify)
                .await;

            let duplicate_window = context.current() + Duration::from_millis(300);
            loop {
                select! {
                    _ = context.sleep_until(duplicate_window) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!("duplicate leader nullify should not retrigger fast-path");
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_leader_nullify_fast_paths_timeout() {
        leader_nullify_fast_paths_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        leader_nullify_fast_paths_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        leader_nullify_fast_paths_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        leader_nullify_fast_paths_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        leader_nullify_fast_paths_timeout::<_, _, RoundRobin>(ed25519::fixture);
        leader_nullify_fast_paths_timeout::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Tests that if the application drops proposal requests, the leader emits `nullify`
    /// immediately instead of waiting for timeout.
    fn dropped_propose_emits_nullify_immediately<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_propose_emits_nullify_immediately".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor.set_drop_proposals(true);
            app_actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_drop_propose_test_{me}"),
                epoch,
                mailbox_size: 128,
                // Long timeouts prove nullify came from fast-path, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(32);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

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

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        (current, leader)
                    }
                    _ => panic!("expected initial update"),
                };

            // Move to a leader view.
            while current_leader != me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } if current > current_view => {
                            response.send(None).unwrap();
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            let target_view = current_view;

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on dropped propose.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_dropped_propose_emits_nullify_immediately() {
        dropped_propose_emits_nullify_immediately(bls12381_threshold_vrf::fixture::<MinPk, _>);
        dropped_propose_emits_nullify_immediately(bls12381_threshold_vrf::fixture::<MinSig, _>);
        dropped_propose_emits_nullify_immediately(bls12381_multisig::fixture::<MinPk, _>);
        dropped_propose_emits_nullify_immediately(bls12381_multisig::fixture::<MinSig, _>);
        dropped_propose_emits_nullify_immediately(ed25519::fixture);
        dropped_propose_emits_nullify_immediately(secp256r1::fixture);
    }

    /// Tests that if the application drops verification requests, the voter emits `nullify`
    /// immediately instead of waiting for timeout.
    fn dropped_verify_emits_nullify_immediately<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_verify_emits_nullify_immediately".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let signing = schemes[0].clone();
            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            app_actor.set_drop_verifications(true);
            app_actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_drop_verify_test_{me}"),
                epoch,
                mailbox_size: 128,
                // Use long timeouts so a fast nullify proves we did not wait for timeout.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(32);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

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
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Initial batcher update.
            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                _ => panic!("expected initial update"),
            }

            // Find a view where we are a verifier (not leader).
            let mut current_view = View::new(1);
            let (target_view, leader) = loop {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                let (new_view, leader) = loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } => {
                            response.send(None).unwrap();
                            if current > current_view {
                                break (current, leader);
                            }
                        }
                        batcher::Message::Constructed(_) => {}
                    }
                };
                current_view = new_view;
                if leader != Participant::new(0) {
                    break (current_view, participants[usize::from(leader)].clone());
                }
            };

            // Trigger verification in target view. The application drops the verify response,
            // which should immediately trigger nullify.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"drop_verify"),
            );
            let contents = (
                proposal.round,
                Sha256::hash(
                    target_view
                        .previous()
                        .unwrap()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                ),
                7u64,
            )
                .encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal).await;

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on dropped verify.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Ensure dropped verify maps to the expected timeout reason metric.
            let encoded = context.encode();
            assert!(
                encoded.lines().any(|line| {
                    line.contains("_timeouts")
                        && line.contains("reason=\"IgnoredProposal\"")
                        && !line.ends_with(" 0")
                }),
                "expected non-zero timeout metric with reason=IgnoredProposal"
            );
        });
    }

    #[test_traced]
    fn test_dropped_verify_emits_nullify_immediately() {
        dropped_verify_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        dropped_verify_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(ed25519::fixture);
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Tests that permanently invalid proposal ancestry fast-paths `nullify`
    /// instead of waiting for the local timeout.
    fn invalid_ancestry_emits_nullify_immediately<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S> + Default,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"invalid_ancestry_emits_nullify_immediately".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                L::default(),
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_mins(60),
                mocks::application::Certifier::Sometimes,
            )
            .await;

            // Advance until we are a verifier in a post-finalization view.
            let me = Participant::new(0);
            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        (current, leader)
                    }
                    _ => panic!("expected initial update"),
                };

            while current_view == View::new(1) || current_leader == me {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } if current > current_view => {
                            response.send(None).unwrap();
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            // Inject a proposal whose parent is below the finalized floor.
            let target_view = current_view;
            let invalid_parent = target_view
                .previous()
                .expect("target view must have a finalized predecessor")
                .previous()
                .unwrap_or(View::zero());
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                invalid_parent,
                Sha256::hash(b"invalid_parent_before_finalized"),
            );
            mailbox.proposal(proposal).await;

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on invalid ancestry.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Ensure invalid ancestry maps to the expected timeout reason metric.
            let encoded = context.encode();
            assert!(
                encoded.lines().any(|line| {
                    line.contains("_timeouts")
                        && line.contains("reason=\"InvalidProposal\"")
                        && !line.ends_with(" 0")
                }),
                "expected non-zero timeout metric with reason=InvalidProposal"
            );
        });
    }

    #[test_traced]
    fn test_invalid_ancestry_emits_nullify_immediately() {
        invalid_ancestry_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(ed25519::fixture);
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Tests that a later dropped verification still yields network voting after
    /// prior successful participation.
    fn dropped_verify_still_votes_after_prior_participation<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_verify_still_votes_after_prior_participation".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), application_cfg);
            app_actor.set_drop_verifications(true);
            app_actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_dropped_verify_after_participation_{me}"),
                epoch,
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(250),
                certification_timeout: Duration::from_millis(250),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.clone(), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(64);
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

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
            let observer = participants[1].clone();
            let (_, mut observer_vote_receiver) = oracle
                .control(observer.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    me.clone(),
                    observer,
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        (current, leader)
                    }
                    _ => panic!("expected initial update"),
                };

            // Move to a view where we are leader.
            while current_leader != me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } if current > current_view => {
                            response.send(None).unwrap();
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }
            let leader_view = current_view;

            // Wait until we actually broadcast a vote in our leader view.
            let ready_deadline = context.current() + Duration::from_secs(1);
            let mut became_ready = false;
            loop {
                select! {
                    _ = context.sleep_until(ready_deadline) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    },
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        if vote.view() == leader_view {
                            became_ready = true;
                            break;
                        }
                    },
                }
            }
            assert!(
                became_ready,
                "expected a network vote in leader view {leader_view}"
            );

            // Move to a non-leader view to trigger dropped verification.
            let (target_view, target_leader) = loop {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(current_view.get().to_be_bytes().as_slice()),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox
                    .resolved(Certificate::Finalization(finalization))
                    .await;

                let mut found = None;
                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current,
                            leader,
                            response,
                            ..
                        } if current > current_view => {
                            response.send(None).unwrap();
                            current_view = current;
                            if leader != me_idx {
                                found = Some((current, participants[usize::from(leader)].clone()));
                            }
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    }
                }
                if let Some(target) = found {
                    break target;
                }
            };

            // This verify request will be dropped by the application.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"drop_verify_after_ready"),
            );
            let contents = (
                proposal.round,
                Sha256::hash(
                    target_view
                        .previous()
                        .unwrap()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                ),
                11u64,
            )
                .encode();
            relay.broadcast(&target_leader, (proposal.payload, contents));
            mailbox.proposal(proposal).await;

            // We should still broadcast for target_view (typically a nullify after timeout).
            let target_deadline = context.current() + Duration::from_secs(1);
            let mut saw_target_network_vote = false;
            loop {
                select! {
                    _ = context.sleep_until(target_deadline) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        batcher::Message::Constructed(_) => {}
                    },
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        if vote.view() == target_view {
                            saw_target_network_vote = true;
                            break;
                        }
                    },
                }
            }
            assert!(
                saw_target_network_vote,
                "expected a network vote for target view {target_view} after dropped verification"
            );
        });
    }

    #[test_traced]
    fn test_dropped_verify_still_votes_after_prior_participation() {
        dropped_verify_still_votes_after_prior_participation(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        dropped_verify_still_votes_after_prior_participation(ed25519::fixture);
        dropped_verify_still_votes_after_prior_participation(secp256r1::fixture);
    }

    /// Tests that after replay, we do not re-certify views that have already
    /// been certified or finalized. Tests both scenarios in the same journal:
    /// 1. Finalization at view 2 (certify never called)
    /// 2. Notarization at view 3 with certification (certify called once)
    ///
    /// After restart, certify should not be called for either view.
    fn no_recertification_after_replay<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_recertification_after_replay".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Track certify calls across restarts
            let certify_calls: Arc<Mutex<Vec<Sha256Digest>>> = Arc::new(Mutex::new(Vec::new()));
            let tracker = certify_calls.clone();

            let elector = L::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());
            let me = participants[0].clone();

            // Create application with certify tracking
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(move |d| {
                    tracker.lock().push(d);
                    true
                })),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "no_recertification_after_replay".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter"), voter_cfg);

            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for initial batcher notification
            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            // Step 1: Send finalization for view 2 (certify should NOT be called)
            let view2 = View::new(2);
            let proposal2 = Proposal::new(
                Round::new(Epoch::new(333), view2),
                View::new(1),
                Sha256::hash(b"finalized_payload"),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal2, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for finalization
            loop {
                if let batcher::Message::Update {
                    finalized,
                    response,
                    ..
                } = batcher_receiver.recv().await.unwrap()
                {
                    response.send(None).unwrap();
                    if finalized >= view2 {
                        break;
                    }
                }
            }

            assert_eq!(
                certify_calls.lock().len(),
                0,
                "certify should not be called for finalization"
            );

            // Step 2: Send notarization for view 3 (certify SHOULD be called)
            let view3 = View::new(3);
            let digest3 = Sha256::hash(b"payload_for_certification");
            let proposal3 = Proposal::new(Round::new(Epoch::new(333), view3), view2, digest3);

            // Broadcast payload and send proposal
            let contents = (proposal3.round, proposal2.payload, 0u64).encode();
            relay.broadcast(&me, (digest3, contents));
            mailbox.proposal(proposal3.clone()).await;

            // Send notarization
            let (_, notarization) = build_notarization(&schemes, &proposal3, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Wait for view advancement (certification complete)
            loop {
                if let batcher::Message::Update {
                    current, response, ..
                } = batcher_receiver.recv().await.unwrap()
                {
                    response.send(None).unwrap();
                    if current > view3 {
                        break;
                    }
                }
            }

            assert_eq!(
                certify_calls.lock().len(),
                1,
                "certify should be called once for notarization"
            );

            // Restart voter
            handle.abort();

            // Create new application with same tracker
            let tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(move |d| {
                    tracker.lock().push(d);
                    true
                })),
            };
            let (actor, application) =
                mocks::application::Application::new(context.with_label("app2"), app_cfg);
            actor.start();

            let page_cache = CacheRef::from_pooler(
                context.with_label("cache_restarted"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "no_recertification_after_replay".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, _mailbox) = Actor::new(context.with_label("voter_restarted"), voter_cfg);

            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete
            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            // Give time for any erroneous certification attempts
            context.sleep(Duration::from_millis(100)).await;

            // Verify no additional certify calls after replay
            assert_eq!(
                certify_calls.lock().len(),
                1,
                "certify should not be called again after replay"
            );
        });
    }

    #[test_traced]
    fn test_no_recertification_after_replay() {
        no_recertification_after_replay::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        no_recertification_after_replay::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        no_recertification_after_replay::<_, _, RoundRobin>(bls12381_multisig::fixture::<MinPk, _>);
        no_recertification_after_replay::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        no_recertification_after_replay::<_, _, RoundRobin>(ed25519::fixture);
        no_recertification_after_replay::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// When the voter is the leader of a view and builds its own proposal, it
    /// must not subsequently ask the automaton to verify that same proposal.
    ///
    /// This is guarded by `Slot::built` (which sets `status = Verified` and
    /// `requested_verify = true`) and by `Round::verify_ready` short-circuiting
    /// for leader-owned views. This test asserts the end-to-end invariant on
    /// the live path (no restart): after calling `automaton.propose`, the voter
    /// must never call `automaton.verify` for the produced payload.
    fn no_self_verify_when_proposing<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_verify_when_proposing".to_vec();
        let partition = "no_self_verify_when_proposing".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            // Install propose + verify observers from the start so we can assert the
            // leader's propose call fires but no verify call is issued for our proposal.
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the voter wired to the observing application.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter"), voter_cfg);
            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the voter to time out (leader_timeout) and construct a Nullify
            // for the view. By that point the voter has already run the full propose
            // flow (so propose_observer should have fired) and any spurious verify for
            // the same payload would have fired before the timeout.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the live invariant: propose fired (precondition proving the leader
            // flow ran) but verify did not fire for the payload we just built.
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                proposed.contains(&target_view),
                "test precondition: voter must have called automaton.propose for the leader-owned view (observed: {proposed:?})"
            );
            assert!(
                !verified.contains(&target_view),
                "voter must not verify its own leader-built proposal (observed: {verified:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_verify_when_proposing() {
        no_self_verify_when_proposing(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_verify_when_proposing(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_verify_when_proposing(bls12381_multisig::fixture::<MinPk, _>);
        no_self_verify_when_proposing(bls12381_multisig::fixture::<MinSig, _>);
        no_self_verify_when_proposing(ed25519::fixture);
        no_self_verify_when_proposing(secp256r1::fixture);
    }

    /// Restart analogue of `no_self_verify_when_proposing`: after the voter has
    /// proposed and journaled a local notarize as leader, restarting must not
    /// cause the voter to re-propose or to verify its own proposal when it is
    /// re-delivered (e.g. via peer echo through the automaton).
    ///
    /// Replay of the journaled local notarize must restore the slot's proposal,
    /// `requested_build`, and `requested_verify` flags so that:
    /// - `should_build` returns false on the next run-loop iteration (no new
    ///   `automaton.propose` call for a payload the voter already proposed
    ///   and voted on pre-crash), and
    /// - subsequent delivery of the same proposal is a no-op (no
    ///   `automaton.verify` call for a payload the voter built itself).
    fn no_self_propose_or_verify_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_propose_or_verify_after_restart".to_vec();
        let partition = "no_self_propose_or_verify_after_restart".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            // Pre-restart: plain application (no observers) so the voter can
            // cleanly propose and journal its own notarize vote for view 2.
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor.start();

            // Build and start the pre-restart voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter"), voter_cfg);
            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the voter to emit its own notarize (journaled). The captured
            // proposal is reused post-restart to exercise the re-delivery path.
            let proposal = loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        break notarize.proposal;
                    }
                    batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                    batcher::Message::Constructed(_) => {}
                }
            };

            // Restart: abort the voter and construct a fresh application with
            // propose + verify observers to catch any spurious work for the
            // leader-owned view that has a journaled local notarize vote.
            handle.abort();
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) = mocks::application::Application::new(
                context.with_label("app_restarted"),
                app_cfg,
            );
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the post-restart voter against the same journal partition.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(context.with_label("cache_restarted"), PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) =
                Actor::new(context.with_label("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete; confirm we re-entered the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::new(0));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Re-deliver the proposal via the automaton, simulating peer echo after
            // restart. Any spurious propose/verify for this view would fire on the next
            // run-loop iteration. Then wait for leader_timeout to fire a Nullify,
            // proving the voter ran its full flow without ever advancing.
            mailbox.proposal(proposal.clone()).await;
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the restart invariant: neither propose nor verify fires post-restart
            // for a leader-owned view whose journaled notarize replay should have
            // restored the slot's proposal state.
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                !proposed.contains(&target_view),
                "voter must not propose for a leader-owned view after restart (observed: {proposed:?})"
            );
            assert!(
                !verified.contains(&target_view),
                "voter must not verify its own leader-built proposal after restart (observed: {verified:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_propose_or_verify_after_restart() {
        no_self_propose_or_verify_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_propose_or_verify_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_propose_or_verify_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        no_self_propose_or_verify_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        no_self_propose_or_verify_after_restart(ed25519::fixture);
        no_self_propose_or_verify_after_restart(secp256r1::fixture);
    }

    /// After restart, a proposal we already voted on must not be re-verified
    /// when it is re-delivered to the voter (e.g. via the automaton after
    /// peer vote aggregation reconstructs it).
    ///
    /// Uses a view where we are a follower (so `verify_ready` does not
    /// short-circuit). Pre-restart the voter verifies the leader's proposal,
    /// emits a `Notarize` vote, and journals it. Post-restart the voter
    /// replays the journaled `Notarize`; the proposal must be restored as
    /// `Verified` so that re-delivering the proposal does not trigger another
    /// `automaton.verify` call.
    fn no_self_verify_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_verify_after_restart".to_vec();
        let partition = "no_self_verify_after_restart".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 3 -> leader=Participant::new(1).
            // We are Participant::new(0), so view 3 is a follower view.
            let target_view = View::new(3);
            let target_leader_idx = 1usize;
            let me = participants[0].clone();
            let leader_pk = participants[target_leader_idx].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            // Pre-restart: plain application (no observers) so the voter can verify
            // the leader's proposal and journal its own notarize vote for view 3.
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app"), app_cfg);
            app_actor.start();

            // Build and start the pre-restart voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter"), voter_cfg);
            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to view 3 via a synthetic finalization for
            // view 2. `advance_to_view` uses Sha256::hash(prev_view.to_be_bytes()) as the
            // parent payload, which we reuse below.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { response, .. } => {
                        response.send(None).unwrap();
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Simulate the leader's proposal: broadcast its payload contents to the
            // application via the relay, then deliver the proposal to the voter.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"follower_proposal"),
            );
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader_pk, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Wait for our local notarize (journaled) so replay has something to restore.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        assert_eq!(notarize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Restart: abort the voter and construct a fresh application with
            // propose + verify observers to catch any spurious work for the
            // follower view that has a journaled local notarize vote.
            handle.abort();
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) = mocks::application::Application::new(
                context.with_label("app_restarted"),
                app_cfg,
            );
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the post-restart voter against the same journal partition.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(context.with_label("cache_restarted"), PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) =
                Actor::new(context.with_label("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete; confirm we re-entered the follower view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        response,
                        ..
                    } => {
                        response.send(None).unwrap();
                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::from_usize(target_leader_idx));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Re-deliver the proposal via the automaton (simulating peer echo after restart).
            // Any spurious verify for the follower view would fire on the next run-loop
            // iteration after the proposal is processed. We then wait for the voter to time
            // out (leader_timeout) and construct a Nullify for the view: by that point the
            // run loop has had ample opportunity to request verification, and emitting a
            // Nullify proves the voter reached the timeout path without ever advancing.
            mailbox.proposal(proposal.clone()).await;
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the restart invariant: verify does not fire for the previously-voted
            // follower proposal (primary) and propose does not fire for the follower view
            // (trivially, since we are not its leader).
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                !verified.contains(&target_view),
                "voter must not request verification for a previously-voted view after restart (observed: {verified:?})"
            );
            assert!(
                !proposed.contains(&target_view),
                "voter must not propose for a previously-voted view after restart (observed: {proposed:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_verify_after_restart() {
        no_self_verify_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_verify_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_verify_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        no_self_verify_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        no_self_verify_after_restart(ed25519::fixture);
        no_self_verify_after_restart(secp256r1::fixture);
    }

    /// Test that in-flight certification requests are cancelled when finalization occurs.
    ///
    /// 1. Use a very long certify latency to ensure certification is in-flight.
    /// 2. Send a notarization to trigger certification.
    /// 3. Send a finalization for the same view before certification completes.
    /// 4. Verify that no Certified message is sent to the resolver.
    fn certification_cancelled_on_finalization<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "cert_cancel_test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (actor, mut mailbox) = Actor::new(context.with_label("voter"), cfg);

            let (resolver_sender, mut resolver_receiver) = mpsc::channel(10);
            let resolver = resolver::Mailbox::new(resolver_sender);

            let (batcher_sender, mut batcher_receiver) = mpsc::channel(1024);
            let batcher = batcher::Mailbox::new(batcher_sender);

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

            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for initial batcher notification
            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            // Send a notarization for view 5 to trigger certification
            let view5 = View::new(5);
            let digest5 = Sha256::hash(b"payload_to_certify");
            let proposal5 =
                Proposal::new(Round::new(Epoch::new(333), view5), View::new(0), digest5);

            // Broadcast payload
            let contents = (proposal5.round, Sha256::hash(b"genesis"), 42u64).encode();
            relay.broadcast(&me, (digest5, contents));

            // Send proposal to verify
            mailbox.proposal(proposal5.clone()).await;

            // Send notarization
            let (_, notarization) = build_notarization(&schemes, &proposal5, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Wait for certification to start (it will be slow due to latency)
            context.sleep(Duration::from_millis(100)).await;

            // Send finalization for view 5 before certification completes
            let (_, finalization) = build_finalization(&schemes, &proposal5, quorum);
            mailbox
                .recovered(Certificate::Finalization(finalization))
                .await;

            // Wait for finalization to be processed
            loop {
                if let batcher::Message::Update {
                    finalized,
                    response,
                    ..
                } = batcher_receiver.recv().await.unwrap()
                {
                    response.send(None).unwrap();
                    if finalized >= view5 {
                        break;
                    }
                }
            }

            // Wait for resolver finalization message (skip other certificates)
            loop {
                let msg = resolver_receiver
                    .recv()
                    .await
                    .expect("expected resolver msg");
                match msg {
                    MailboxMessage::Certificate(Certificate::Finalization(f)) => {
                        assert_eq!(f.view(), view5);
                        break;
                    }
                    MailboxMessage::Certificate(_) => continue,
                    MailboxMessage::Certified { .. } => {
                        panic!("unexpected Certified message before finalization processed")
                    }
                }
            }

            // Wait longer than certify_latency (2s) to verify certification was cancelled.
            // If certification wasn't cancelled, it would complete and send a Certified message.
            let certified_received = select! {
                msg = resolver_receiver.recv() => {
                    matches!(msg, Some(MailboxMessage::Certified { .. }))
                },
                _ = context.sleep(Duration::from_secs(4)) => false,
            };

            assert!(
                !certified_received,
                "Certified message should NOT have been sent - certification should be cancelled"
            );
        });
    }

    #[test_traced]
    fn test_certification_cancelled_on_finalization() {
        certification_cancelled_on_finalization::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_cancelled_on_finalization::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(ed25519::fixture);
        certification_cancelled_on_finalization::<_, _, RoundRobin>(secp256r1::fixture);
    }

    /// Test that in-flight certification is still reported to resolver after nullification.
    ///
    /// 1. Use a long certify latency so certification remains in-flight.
    /// 2. Send notarization to trigger certification.
    /// 3. Send nullification for the same view before certification completes.
    /// 4. Verify that a Certified message is still sent to resolver when certification completes.
    fn certification_still_reports_to_resolver_after_nullification<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let me = participants[0].clone();
            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();

            let page_cache =
                CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "cert_after_nullification_test".to_string(),
                epoch: Epoch::new(333),
                mailbox_size: 128,
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (actor, mut mailbox) = Actor::new(context.with_label("voter"), cfg);

            let (resolver_sender, mut resolver_receiver) = mpsc::channel(10);
            let resolver = resolver::Mailbox::new(resolver_sender);

            let (batcher_sender, mut batcher_receiver) = mpsc::channel(1024);
            let batcher = batcher::Mailbox::new(batcher_sender);

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

            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for initial batcher notification
            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            // Send a notarization for view 5 to trigger certification
            let view5 = View::new(5);
            let digest5 = Sha256::hash(b"payload_to_certify");
            let proposal5 =
                Proposal::new(Round::new(Epoch::new(333), view5), View::new(0), digest5);

            // Broadcast payload
            let contents = (proposal5.round, Sha256::hash(b"genesis"), 42u64).encode();
            relay.broadcast(&me, (digest5, contents));

            // Send proposal and notarization
            mailbox.proposal(proposal5.clone()).await;
            let (_, notarization) = build_notarization(&schemes, &proposal5, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Wait for certification to start (it will be slow due to latency)
            context.sleep(Duration::from_millis(100)).await;

            // Send nullification for the same view before certification completes
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), view5), quorum);
            mailbox
                .recovered(Certificate::Nullification(nullification))
                .await;

            // Even after nullification, late certification should still be forwarded to resolver.
            let reported = loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success } if view == view5 =>
                            break Some(success),
                        MailboxMessage::Certified { .. } | MailboxMessage::Certificate(_) => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { response, .. } = msg.unwrap() {
                            response.send(None).unwrap();
                        }
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        break None;
                    },
                }
            };

            assert_eq!(
                reported,
                Some(true),
                "expected resolver to receive successful certification after nullification"
            );
        });
    }

    #[test_traced]
    fn test_certification_still_reports_to_resolver_after_nullification() {
        certification_still_reports_to_resolver_after_nullification::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            ed25519::fixture,
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            secp256r1::fixture,
        );
    }

    /// Regression: a notarization arriving after nullification for the same view
    /// should still trigger certification.
    fn late_notarization_after_nullification_still_certifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"late_notarization_after_nullification".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network.
            // Build participants and voter.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                mocks::application::Certifier::Always,
            )
            .await;

            // Move into a concrete current view.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Nullify current view first.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), target_view), quorum);
            mailbox
                .resolved(Certificate::Nullification(nullification))
                .await;

            // Then provide notarization for that same view.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"late_notarization_after_nullification"),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            let certified = loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success } if view == target_view => {
                            break Some(success);
                        }
                        MailboxMessage::Certified { .. } | MailboxMessage::Certificate(_) => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { response, .. } = msg.unwrap() {
                            response.send(None).unwrap();
                        }
                    },
                    _ = context.sleep(Duration::from_secs(6)) => break None,
                }
            };

            assert_eq!(
                certified,
                Some(true),
                "expected notarization after nullification to still trigger certification"
            );
        });
    }

    #[test_traced]
    fn test_late_notarization_after_nullification_still_certifies() {
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(ed25519::fixture);
        late_notarization_after_nullification_still_certifies::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: timeout -> receive notarization -> certify.
    /// This test does NOT send a notarize vote first (we timeout before receiving a proposal).
    fn certification_after_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(100),
                mocks::application::Certifier::Always,
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_ne!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should not be leader at view 3"
            );

            // Wait for timeout (nullify vote) WITHOUT sending notarize first
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(15)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate (simulating delayed network delivery)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"timeout_test"),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update {
                            current, response, ..
                        } = msg.unwrap()
                        {
                            response.send(None).unwrap();
                            if current > target_view {
                                break true;
                            }
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (timeout case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_timeout() {
        certification_after_timeout::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certification_after_timeout::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certification_after_timeout::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        certification_after_timeout::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        certification_after_timeout::<_, _>(ed25519::fixture);
        certification_after_timeout::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: notarize -> timeout -> receive notarization -> certify.
    /// This test runs when we are NOT the leader (receiving proposal from another participant).
    fn certification_after_notarize_timeout_as_follower<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_notarize_timeout_as_follower".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(100),
                mocks::application::Certifier::Always,
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_ne!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should not be leader at view 3"
            );

            // Create and send proposal as if from the leader (participant 1)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"follower_test"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Wait for notarize vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize vote");
                    },
                }
            }

            // Trigger timeout
            context.sleep(Duration::from_secs(11)).await;

            // Wait for nullify vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update {
                            current, response, ..
                        } = msg.unwrap()
                        {
                            response.send(None).unwrap();
                            if current > target_view {
                                break true;
                            }
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (follower case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_notarize_timeout_as_follower() {
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(ed25519::fixture);
        certification_after_notarize_timeout_as_follower::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: notarize -> timeout -> receive notarization -> certify.
    /// This test runs when we ARE the leader (proposing ourselves).
    fn certification_after_notarize_timeout_as_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_notarize_timeout_as_leader".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(100),
                mocks::application::Certifier::Always,
            )
            .await;

            // Advance to view 2 where we ARE the leader.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 2: leader = 0 (us)
            let target_view = View::new(2);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_eq!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should be leader at view 2"
            );

            // As leader, wait for our own notarize vote (automaton will propose)
            let proposal = loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                        {
                            break n.proposal.clone();
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize vote as leader");
                    },
                }
            };

            // Trigger timeout
            context.sleep(Duration::from_secs(11)).await;

            // Wait for nullify vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate (as if other participants formed it)
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update {
                            current, response, ..
                        } = msg.unwrap()
                        {
                            response.send(None).unwrap();
                            if current > target_view {
                                break true;
                            }
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (leader case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_notarize_timeout_as_leader() {
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(ed25519::fixture);
        certification_after_notarize_timeout_as_leader::<_, _>(secp256r1::fixture);
    }

    /// Tests that when certification returns a cancelled receiver, the voter doesn't hang
    /// and continues to make progress (via voting to nullify the view that could not be certified).
    fn cancelled_certification_does_not_hang<S, F>(mut fixture: F, traces: TraceStorage)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Cancel
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_mins(60),
                mocks::application::Certifier::Cancel,
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"test_proposal"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay
                .broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Build and send notarization so the voter tries to certify
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            // Certification will be cancelled, so the voter should eventually timeout
            // and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Constructed(Vote::Nullify(nullify)) if nullify.view() == target_view => {
                                break;
                            }
                            batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} despite cancelled certification",
                        );
                    },
                }
            }

            // Verify the "failed to certify proposal" log was emitted with the correct round
            let expected_round = format!("Round {{ epoch: Epoch(333), view: View({target_view}) }}");
            traces
                .get_by_level(Level::DEBUG)
                .expect_event(|event| {
                    event.metadata.content == "failed to certify proposal"
                        && event
                            .metadata
                            .fields
                            .iter()
                            .any(|(name, value)| name == "err" && value == "RecvError(())")
                        && event
                            .metadata
                            .fields
                            .iter()
                            .any(|(name, value)| name == "round" && value == &expected_round)
                })
                .unwrap();
        });
    }

    #[test_collect_traces]
    fn test_cancelled_certification_does_not_hang(traces: TraceStorage) {
        cancelled_certification_does_not_hang(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_multisig::fixture::<MinPk, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_multisig::fixture::<MinSig, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(ed25519::fixture, traces.clone());
        cancelled_certification_does_not_hang(secp256r1::fixture, traces);
    }

    /// Regression: a canceled certification attempt must not be persisted as failure.
    ///
    /// We first trigger a canceled certify receiver, restart the voter, and then require:
    /// 1. successful certification for the same view from replayed notarization state, and
    /// 2. no immediate timeout/nullify for that view after restart.
    fn cancelled_certification_recertifies_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"cancelled_cert_restart_recertify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::new());

            let partition = "cancelled_certification_recertifies_after_restart".to_string();
            let epoch = Epoch::new(333);

            // First run: certification receiver gets cancelled.
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Cancel,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app_cancel"), app_cfg);
            app_actor.start();

            let page_cache = CacheRef::from_pooler(
                context.with_label("cache_cancel"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                mailbox_size: 128,
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, mut mailbox) = Actor::new(context.with_label("voter_cancel"), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"restart_recertify_payload"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            // Give the canceled certification attempt time to run before restart.
            context.sleep(Duration::from_millis(200)).await;

            // Sanity check: canceled certification should not have advanced this view yet.
            let advanced_before_restart = select! {
                msg = batcher_receiver.recv() => {
                    if let batcher::Message::Update {
                        current, response, ..
                    } = msg.unwrap()
                    {
                        response.send(None).unwrap();
                        current > target_view
                    } else {
                        false
                    }
                },
                _ = context.sleep(Duration::from_millis(200)) => false,
            };
            assert!(
                !advanced_before_restart,
                "view should not advance before restart when certification receiver is canceled"
            );

            // Restart voter.
            handle.abort();

            // Second run: certification should succeed from replayed state.
            // Use a longer certify latency so there is a real window where an
            // incorrect immediate nullify could fire after restart.
            let app_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.with_label("app_restarted"), app_cfg);
            app_actor.start();

            let page_cache = CacheRef::from_pooler(
                context.with_label("cache_restarted"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition,
                epoch,
                mailbox_size: 128,
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                activity_timeout: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };
            let (voter, _mailbox) = Actor::new(context.with_label("voter_restarted"), voter_cfg);

            let (resolver_sender, mut resolver_receiver) = mpsc::channel(8);
            let (batcher_sender, mut batcher_receiver) = mpsc::channel(8);
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { response, .. } =
                batcher_receiver.recv().await.unwrap()
            {
                response.send(None).unwrap();
            }

            loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success } if view == target_view => {
                            assert!(success, "expected successful certification after restart for canceled certification view");
                            break;
                        }
                        MailboxMessage::Certified { .. } | MailboxMessage::Certificate(_) => {}
                    },
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Constructed(Vote::Nullify(nullify))
                                if nullify.view() == target_view =>
                            {
                                panic!("unexpected immediate nullify for view {target_view} after restart");
                            }
                            batcher::Message::Update { response, .. } => {
                                response.send(None).unwrap();
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "timed out waiting for successful certification for restarted view {target_view}"
                        );
                    },
                }
            };

            // Give reporter a moment to ingest any late events and ensure no nullify artifacts
            // were emitted for the restarted target view.
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                !reporter.nullifies.lock().contains_key(&target_view),
                "did not expect nullify votes for restarted view {target_view}"
            );
            assert!(
                !reporter.nullifications.lock().contains_key(&target_view),
                "did not expect nullification certificate for restarted view {target_view}"
            );
        });
    }

    #[test_traced]
    fn test_cancelled_certification_recertifies_after_restart() {
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(ed25519::fixture);
        cancelled_certification_recertifies_after_restart::<_, _>(secp256r1::fixture);
    }

    /// Demonstrates that validators in future views cannot retroactively help
    /// stuck validators escape via nullification.
    ///
    /// This test extends the previous scenario to show that:
    /// 1. A stuck validator (view 3) cannot be rescued by notarizations from future views
    /// 2. The only escape route is a finalization certificate (which requires Byzantine cooperation)
    ///
    /// Once the f+1 honest validators certify view 3 and advance to view 4,
    /// they can only vote to nullify view 4 (their current view) without equivocating.
    /// The `timeout` function only votes to nullify `self.view` (current view).
    fn only_finalization_rescues_validator<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 4;
        let quorum = quorum(n);
        let namespace = b"future_notarization_no_rescue".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            // Setup voter with Certifier::Cancel to simulate missing verification context.
            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector.clone(),
                Duration::from_secs(2),
                Duration::from_secs(3),
                Duration::from_secs(1),
                mocks::application::Certifier::Cancel,
            )
            .await;

            // Advance to view 3
            let view_3 = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                view_3,
            )
            .await;

            let proposal_3 = Proposal::new(
                Round::new(Epoch::new(333), view_3),
                view_3.previous().unwrap(),
                Sha256::hash(b"view_3_proposal"),
            );
            let leader = participants[1].clone();
            let contents = (proposal_3.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal_3.payload, contents));
            mailbox.proposal(proposal_3.clone()).await;

            let (_, notarization_3) = build_notarization(&schemes, &proposal_3, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization_3))
                .await;

            // Wait for the first nullify vote (confirms stuck state)
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n)) if n.view() == view_3 =>
                            break,
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(10)) => {
                        panic!("expected nullify vote for view 3");
                    },
                }
            }

            // Now simulate what the "advanced" validators (f+1 honest with context) are doing:
            // They certified view 3 and advanced to view 4, where they're making progress.
            // Send a notarization for view 4 to the stuck validator.
            let view_4 = View::new(4);
            let proposal_4 = Proposal::new(
                Round::new(Epoch::new(333), view_4),
                view_3, // Parent is view 3 (certified by the advanced validators)
                Sha256::hash(b"view_4_proposal"),
            );
            let (_, notarization_4) = build_notarization(&schemes, &proposal_4, quorum);

            // Send the view 4 notarization to the stuck validator
            mailbox
                .resolved(Certificate::Notarization(notarization_4))
                .await;

            // The stuck validator should still not advance.
            //
            // Receiving a notarization for view 4 doesn't help because:
            // 1. add_notarization() does not call enter_view() - it only adds to certification_candidates
            // 2. To advance past view 3, the validator needs EITHER:
            //    a. Certification of view 3 to succeed (impossible - no context)
            //    b. A nullification certificate for view 3 (impossible - only f votes)
            //    c. A finalization certificate (requires Byzantine to vote finalize)
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Update {
                                current, response, ..
                            } => {
                                response.send(None).unwrap();
                                if current > view_3 {
                                    break true;
                                }
                            }
                            batcher::Message::Constructed(Vote::Nullify(n)) => {
                                // Still voting nullify for view 3 - expected
                                assert_eq!(
                                    n.view(),
                                    view_3,
                                    "should only vote nullify for stuck view"
                                );
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };

            assert!(
                !advanced,
                "receiving a notarization for view 4 should NOT rescue the stuck validator - \
                 they still can't certify view 3 (no context) and can't form a nullification \
                 (not enough votes). The f+1 honest validators who advanced to view 4 cannot \
                 retroactively help because they can only vote nullify for their current view (4), \
                 not for view 3."
            );

            // HOWEVER: A finalization certificate WOULD rescue the stuck validator.
            // If the Byzantine validators eventually cooperate and vote finalize,
            // the finalization would abort the stuck certification and advance the view.
            //
            // Let's demonstrate this escape route works (if Byzantine cooperate):
            let (_, finalization_4) = build_finalization(&schemes, &proposal_4, quorum);
            mailbox
                .resolved(Certificate::Finalization(finalization_4))
                .await;

            // Now the validator SHOULD advance (finalization aborts stuck certification)
            let rescued = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update {
                            current, response, ..
                        } = msg.unwrap()
                        {
                            response.send(None).unwrap();
                            if current > view_4 {
                                break true;
                            }
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };

            assert!(
                rescued,
                "a finalization certificate SHOULD rescue the stuck validator - \
                 this is the ONLY escape route, but it requires Byzantine cooperation \
                 (they must vote finalize). If Byzantine permanently withhold finalize votes, \
                 the stuck validators are permanently excluded from consensus."
            );
        });
    }

    #[test_traced]
    fn test_only_finalization_rescues_validator() {
        only_finalization_rescues_validator::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        only_finalization_rescues_validator::<_, _>(ed25519::fixture);
        only_finalization_rescues_validator::<_, _>(secp256r1::fixture);
    }

    /// Tests that when certification explicitly fails (returns false), the voter:
    /// 1. Can vote nullify even after having voted notarize
    /// 2. Will emit a nullify vote immediately after certification failure
    ///
    /// This simulates the coding marshal scenario where:
    /// - verify() returns true (shard validity passes)
    /// - Voter votes notarize
    /// - Notarization forms
    /// - certify() returns false (block context mismatch discovered during deferred_verify)
    /// - Voter should vote nullify to attempt to advance
    ///
    /// The liveness concern is: if only f honest validators can vote nullify (the ones who
    /// never saw the shard/never verified), then nullification quorum (2f+1) cannot form
    /// since the f+1 honest who voted notarize need to also vote nullify.
    fn certification_failure_allows_nullify_after_notarize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"cert_fail_nullify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Custom that always returns false
            // This simulates coding marshal's deferred_verify finding context mismatch
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(100),  // Long timeout to prove nullify comes from cert failure
                Duration::from_secs(100),
                Duration::from_secs(100),
                mocks::application::Certifier::Custom(Box::new(|_| false)),
            )
            .await;

            // Advance to view 3 where we're a follower.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"test_proposal"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Wait for notarize vote first (verification passes)
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n)) if n.view() == target_view => {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // Build and send notarization so the voter tries to certify
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            // Certification will fail (returns false), so the voter should emit a nullify vote.
            // This must happen quickly (not after 100s timeout) to prove it's from cert failure.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify)) if nullify.view() == target_view => {
                            // Successfully voted nullify after having voted notarize
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} after certification failure, \
                             even though it already voted notarize"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_certification_failure_allows_nullify_after_notarize() {
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(ed25519::fixture);
        certification_failure_allows_nullify_after_notarize::<_, _>(secp256r1::fixture);
    }

    /// Verify that a voter recovers via timeout when certification hangs indefinitely.
    ///
    /// This simulates the scenario where a notarization forms but the block is
    /// unrecoverable (e.g., proposer is dead and shard gossip didn't deliver enough
    /// shards for reconstruction). In this case, `certify()` subscribes to the block
    /// but the subscription never resolves. The voter must rely on the view timeout
    /// to emit a nullify vote and advance the chain.
    ///
    /// Unlike `Cancel` mode (where the certify receiver errors immediately), `Pending`
    /// mode holds the certify sender alive so the future never completes, forcing the
    /// voter to recover purely through its timeout mechanism.
    fn pending_certification_nullifies_on_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"pending_cert_nullify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Pending (certify hangs indefinitely).
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(3),
                Duration::from_secs(4),
                Duration::from_mins(60),
                mocks::application::Certifier::Pending,
            )
            .await;

            // Advance to view 3 where we're a follower.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"test_proposal"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Wait for notarize vote (verification passes).
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // Build and send notarization so the voter tries to certify.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            // Certification hangs (sender held alive, receiver pending). The voter
            // must recover via the view timeout and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            // Timeout fired and voter emitted nullify despite
                            // certification being indefinitely pending.
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(8)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} via timeout \
                             when certification hangs indefinitely",
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_pending_certification_nullifies_on_timeout() {
        pending_certification_nullifies_on_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        pending_certification_nullifies_on_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        pending_certification_nullifies_on_timeout::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        pending_certification_nullifies_on_timeout::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        pending_certification_nullifies_on_timeout::<_, _>(ed25519::fixture);
        pending_certification_nullifies_on_timeout::<_, _>(secp256r1::fixture);
    }

    /// Regression: once a proposal is received, leader timeout must no longer fire for that view.
    ///
    /// We require:
    /// 1. No nullify before `certification_timeout` even though `leader_timeout` has elapsed.
    /// 2. Nullify eventually arrives only after `certification_timeout` when no
    ///    certificate progress occurs.
    fn proposal_clears_leader_timeout_before_certification_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"proposal_clears_leader_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_mins(60),
                mocks::application::Certifier::Always,
            )
            .await;

            // Advance to a follower view.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Submit proposal quickly so leader timeout is cleared.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"proposal_clears_leader_timeout"),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // Ensure proposal verification path ran.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(v)) if v.view() == target_view => {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // `leader_timeout` is 1s and `certification_timeout` is 5s. We should not
            // see nullify in this 2s window after proposal handling, even though
            // leader timeout has elapsed.
            let no_nullify_deadline = context.current() + Duration::from_secs(2);
            loop {
                select! {
                    _ = context.sleep_until(no_nullify_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!(
                                "received nullify for view {target_view} before certification timeout"
                            );
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    }
                }
            }

            // After certification timeout elapses, timeout recovery must emit nullify.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        panic!(
                            "expected nullify for view {target_view} after certification timeout"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_proposal_clears_leader_timeout_before_certification_timeout() {
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(ed25519::fixture);
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(secp256r1::fixture);
    }

    /// Regression: proposals recovered from notarization certificates must clear the
    /// current view's leader timeout without emitting a local notarize vote.
    ///
    /// We require:
    /// 1. No nullify before `certification_timeout` even though `leader_timeout` has elapsed.
    /// 2. Nullify eventually arrives only after `certification_timeout` when certification
    ///    remains pending.
    fn recovered_proposal_clears_leader_timeout_before_certification_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"recovered_proposal_clears_leader_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_mins(60),
                mocks::application::Certifier::Pending,
            )
            .await;

            // Advance to a follower view.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Recover a notarization that carries the proposal for this view.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(b"recovered_proposal_clears_leader_timeout"),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization))
                .await;

            // `leader_timeout` is 1s and `certification_timeout` is 5s. We should not
            // emit a notarize vote or nullify in this 2s window after certificate handling,
            // even though leader timeout has elapsed.
            let quiet_deadline = context.current() + Duration::from_secs(2);
            loop {
                select! {
                    _ = context.sleep_until(quiet_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(v)) if v.view() == target_view => {
                            panic!(
                                "unexpected notarize for view {target_view} from recovered certificate"
                            );
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!(
                                "received nullify for view {target_view} before certification timeout after recovered certificate"
                            );
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    }
                }
            }

            // After certification timeout elapses, timeout recovery must emit nullify.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        panic!(
                            "expected nullify for view {target_view} after certification timeout with recovered certificate"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_recovered_proposal_clears_leader_timeout_before_certification_timeout() {
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            ed25519::fixture,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            secp256r1::fixture,
        );
    }

    /// Regression: after a timed-out view is nullified and the voter advances,
    /// the next view must start with a fresh leader timeout.
    fn next_view_gets_fresh_timeout_after_prior_view_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"next_view_gets_fresh_timeout_after_prior_view_nullifies".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.clone(),
                participants.clone(),
                true,
            )
            .await;

            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_mins(60),
                mocks::application::Certifier::Always,
            )
            .await;

            // Wait for the initial view 1 batcher update.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, response, ..
                    } => {
                        response.send(None).unwrap();
                        if current == View::new(1) {
                            break;
                        }
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Allow view 1 to time out and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            break;
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected nullify for view 1");
                    },
                }
            }

            // Deliver a nullification certificate for view 1 so the voter enters view 2.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), View::new(1)), quorum);
            mailbox
                .resolved(Certificate::Nullification(nullification))
                .await;

            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(2) =>
                        {
                            panic!(
                                "received nullify for view 2 before its fresh leader timeout elapsed"
                            );
                        }
                        batcher::Message::Update {
                            current, response, ..
                        } => {
                            response.send(None).unwrap();
                            if current == View::new(2) {
                                break;
                            }
                        }
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected voter to advance to view 2");
                    },
                }
            }

            // The old view timed out, but the new view should still get its own leader timeout
            // rather than immediately nullifying on entry.
            let quiet_deadline = context.current() + Duration::from_millis(500);
            loop {
                select! {
                    _ = context.sleep_until(quiet_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(2) =>
                        {
                            panic!(
                                "received nullify for view 2 before its fresh leader timeout elapsed"
                            );
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_next_view_gets_fresh_timeout_after_prior_view_nullifies() {
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(ed25519::fixture);
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(secp256r1::fixture);
    }

    /// Regression: the first view should make progress without timing out when peers are online.
    ///
    /// We require:
    /// 1. No `nullify(1)` is emitted while quorum certificates arrive promptly.
    /// 2. The voter emits `notarize(1)`.
    /// 3. After successful certification, the voter emits `finalize(1)` before
    ///    advancing to view 2.
    fn first_view_progress_without_timeout<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"first_view_progress_without_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.clone(), participants.clone(), true).await;

            let elector = L::default();
            let first_round = Round::new(Epoch::new(333), View::new(1));
            let leader_idx = elector
                .clone()
                .build(schemes[0].participants())
                .elect(first_round, None);
            let leader = participants[usize::from(leader_idx)].clone();

            let (mut mailbox, mut batcher_receiver, _, relay, reporter) = setup_voter(
                &mut context,
                &oracle,
                &participants,
                &schemes,
                elector,
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_mins(60),
                mocks::application::Certifier::Always,
            )
            .await;

            // Wait for initial batcher notification.
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    finalized,
                    response,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                    response.send(None).unwrap();
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build a valid first-view proposal (parent is genesis at view 0).
            let mut hasher = Sha256::default();
            hasher.update(&(bytes::Bytes::from_static(b"genesis"), Epoch::new(333)).encode());
            let genesis = hasher.finalize();
            let proposal = Proposal::new(
                first_round,
                View::zero(),
                Sha256::hash(b"first_view_progress_without_timeout"),
            );
            let contents = (proposal.round, genesis, 0u64).encode();
            relay.broadcast(&leader, (proposal.payload, contents));
            mailbox.proposal(proposal.clone()).await;

            // The voter should notarize view 1 and must not nullify it.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(notarize))
                            if notarize.view() == View::new(1) =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update { response, .. } => response.send(None).unwrap(),
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize for view 1");
                    },
                }
            }

            // Deliver quorum notarization and ensure we finalize + advance to view 2 without nullify.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization))
                .await;

            let deadline = context.current() + Duration::from_secs(3);
            let reached_view2 = loop {
                select! {
                    _ = context.sleep_until(deadline) => break false,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Finalize(finalize))
                            if finalize.view() == View::new(1) =>
                        {
                            break false;
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update {
                            current, response, ..
                        } => {
                            response.send(None).unwrap();
                            if current >= View::new(2) {
                                break true;
                            }
                        }
                        _ => {}
                    },
                }
            };
            assert!(!reached_view2, "view advanced before finalize for view 1");

            let reached_view2 = loop {
                select! {
                    _ = context.sleep_until(deadline) => break false,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update {
                            current, response, ..
                        } => {
                            response.send(None).unwrap();
                            if current >= View::new(2) {
                                break true;
                            }
                        }
                        _ => {}
                    },
                }
            };
            assert!(reached_view2, "expected progress to view 2 from view 1");

            // Give the reporter a moment to receive any late events and verify no first-view nullify artifacts.
            context.sleep(Duration::from_millis(50)).await;
            assert!(
                !reporter.nullifies.lock().contains_key(&View::new(1)),
                "did not expect nullify votes for view 1"
            );
            assert!(
                !reporter.nullifications.lock().contains_key(&View::new(1)),
                "did not expect a nullification certificate for view 1"
            );
        });
    }

    #[test_traced]
    fn test_first_view_progress_without_timeout() {
        first_view_progress_without_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        first_view_progress_without_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(ed25519::fixture);
        first_view_progress_without_timeout::<_, _, RoundRobin>(secp256r1::fixture);
    }
}
