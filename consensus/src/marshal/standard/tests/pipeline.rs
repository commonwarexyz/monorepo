use super::*;
use crate::marshal::ancestry::Ancestry;

#[derive(Clone)]
struct PipelineApp {
    verify_started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    verify_release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    build_started: Arc<Mutex<Option<oneshot::Sender<Ctx>>>>,
    build_release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    build_completed: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    build_dropped: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    policies: Arc<AtomicUsize>,
    builds: Arc<AtomicUsize>,
    block: B,
}

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            tx.send_lossy(());
        }
    }
}

impl crate::Application<Runtime> for PipelineApp {
    type Block = B;
    type Context = Ctx;
    type SigningScheme = S;
    type Input = ();

    async fn handoff_policy(&mut self, _: (Runtime, Ctx)) -> HandoffPolicy {
        self.policies.fetch_add(1, Ordering::SeqCst);
        HandoffPolicy::Build
    }

    async fn propose(
        &mut self,
        (_, context): (Runtime, Ctx),
        _: impl Ancestry<B>,
        _: (),
    ) -> Option<B> {
        assert_eq!(
            self.builds.fetch_add(1, Ordering::SeqCst),
            0,
            "the retained handoff must not be replaced by an ordinary build"
        );
        let mut drop_signal = DropSignal(self.build_dropped.lock().take());
        self.build_started
            .lock()
            .take()
            .unwrap()
            .send_lossy(context);
        let release = self.build_release.lock().take().unwrap();
        release.await.unwrap();
        drop_signal.0.take();
        self.build_completed.lock().take().unwrap().send_lossy(());
        Some(self.block.clone())
    }

    async fn verify(&mut self, _: (Runtime, Ctx), _: impl Ancestry<B>) -> bool {
        let started = self.verify_started.lock().take();
        if let Some(started) = started {
            let release = self.verify_release.lock().take().unwrap();
            started.send_lossy(());
            release.await.unwrap();
        }
        true
    }
}

fn retained_pipeline_handoff(certification_first: bool) {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let victim = participants[3].clone();
        let peer = participants[2].clone();
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;
        let setup = StandardHarness::setup_validator(
            context.child("marshal"),
            &mut oracle,
            victim.clone(),
            ConstantProvider::new(schemes[3].clone()),
        )
        .await;
        let mut marshal = setup.mailbox;
        let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
        let floor_round = Round::new(Epoch::zero(), View::new(1));
        let floor_block = B::new::<Sha256>(
            Ctx {
                round: floor_round,
                leader: participants[1].clone(),
                parent: (View::zero(), genesis.digest()),
            },
            genesis.digest(),
            Height::new(1),
            100,
        );
        let floor_digest = floor_block.digest();
        assert!(marshal.verified(floor_round, floor_block).await);
        let floor_finalization = StandardHarness::make_finalization(
            Proposal::new(floor_round, View::zero(), floor_digest),
            &schemes,
            QUORUM,
        );
        StandardHarness::report_finalization(&mut marshal, floor_finalization.clone()).await;
        let parent_round = Round::new(Epoch::zero(), View::new(2));
        let parent_block = B::new::<Sha256>(
            Ctx {
                round: parent_round,
                leader: peer.clone(),
                parent: (View::new(1), floor_digest),
            },
            floor_digest,
            Height::new(2),
            200,
        );
        let parent_digest = parent_block.digest();
        assert!(
            setup
                .extra
                .broadcast(Recipients::Some(vec![]), parent_block)
                .accepted()
        );
        let round = Round::new(Epoch::zero(), View::new(3));
        let expected_context = Ctx {
            round,
            leader: victim.clone(),
            parent: (View::new(2), parent_digest),
        };
        let block = B::new::<Sha256>(expected_context.clone(), parent_digest, Height::new(3), 300);
        let digest = block.digest();
        let (verify_tx, verify_rx) = oneshot::channel();
        let (verify_release_tx, verify_release_rx) = oneshot::channel();
        let (build_tx, build_rx) = oneshot::channel();
        let (build_release_tx, build_release_rx) = oneshot::channel();
        let (completed_tx, completed_rx) = oneshot::channel();
        let (drop_tx, mut drop_rx) = oneshot::channel();
        let policies = Arc::new(AtomicUsize::new(0));
        let builds = Arc::new(AtomicUsize::new(0));
        let app = PipelineApp {
            verify_started: Arc::new(Mutex::new(Some(verify_tx))),
            verify_release: Arc::new(Mutex::new(Some(verify_release_rx))),
            build_started: Arc::new(Mutex::new(Some(build_tx))),
            build_release: Arc::new(Mutex::new(Some(build_release_rx))),
            build_completed: Arc::new(Mutex::new(Some(completed_tx))),
            build_dropped: Arc::new(Mutex::new(Some(drop_tx))),
            policies: policies.clone(),
            builds: builds.clone(),
            block,
        };
        let control = oracle.control(victim.clone());
        let vote_network = control.register(3, TEST_QUOTA).await.unwrap();
        let certificate_network = control.register(4, TEST_QUOTA).await.unwrap();
        let resolver_network = control.register(5, TEST_QUOTA).await.unwrap();
        let control = oracle.control(peer);
        let (mut vote_sender, mut vote_receiver) = control.register(3, TEST_QUOTA).await.unwrap();
        let (mut certificate_sender, _certificate_receiver) =
            control.register(4, TEST_QUOTA).await.unwrap();
        let _resolver = control.register(5, TEST_QUOTA).await.unwrap();
        setup_network_links(&mut oracle, &participants, LINK).await;
        let wrapper = Deferred::new(
            context.child("wrapper"),
            app,
            marshal.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );
        let engine = simplex::Engine::new(
            context.child("simplex"),
            simplex::config::Config {
                scheme: schemes[3].clone(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(victim.clone()),
                automaton: wrapper.clone(),
                relay: wrapper,
                reporter: marshal.clone(),
                strategy: Sequential,
                partition: format!("retained-pipeline-{certification_first}"),
                mailbox_size: NZUsize!(128),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Finalized(floor_finalization),
                replay_buffer: NZUsize!(1024),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(15),
                timeout_retry: Duration::from_secs(3),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(20),
                    budget: SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(1),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
                pipelined_handoff: false,
            },
        );
        let _engine = engine.start(vote_network, certificate_network, resolver_network);

        // Register the real verification gate before delivering the parent certificate.
        let parent = Proposal::new(parent_round, View::new(1), parent_digest);
        vote_sender.send(
            Recipients::One(victim.clone()),
            Vote::<S, D>::Notarize(Notarize::sign(&schemes[2], parent.clone()).unwrap()).encode(),
            true,
        );
        verify_rx.await.unwrap();
        let votes: Vec<_> = [0usize, 1, 2]
            .into_iter()
            .map(|i| Notarize::sign(&schemes[i], parent.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential).unwrap();
        certificate_sender.send(
            Recipients::One(victim.clone()),
            Certificate::<S, D>::Notarization(notarization).encode(),
            true,
        );
        let built_context = select! {
            result = build_rx => result.expect("handoff build should start"),
            _ = context.sleep(Duration::from_secs(5)) => panic!("handoff build did not start"),
        };
        assert_eq!(built_context, expected_context);
        assert_eq!(policies.load(Ordering::SeqCst), 1);
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        if certification_first {
            verify_release_tx.send_lossy(());
            loop {
                let (sender, message) = vote_receiver.recv().await.unwrap();
                assert_eq!(sender, victim);
                if let Vote::<S, D>::Finalize(vote) = Vote::decode(message).unwrap()
                    && vote.proposal == parent
                {
                    break;
                }
            }
            assert!(matches!(drop_rx.try_recv(), Err(TryRecvError::Empty)));
            assert_eq!(builds.load(Ordering::SeqCst), 1);
            build_release_tx.send_lossy(());
            completed_rx.await.unwrap();
        } else {
            build_release_tx.send_lossy(());
            completed_rx.await.unwrap();
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                marshal.get_verified(round).await.is_none(),
                "the completed candidate must remain staged until its parent certifies"
            );
            loop {
                select! {
                    result = vote_receiver.recv() => {
                        let (sender, message) = result.unwrap();
                        assert_eq!(sender, victim);
                        let proposal = match Vote::<S, D>::decode(message).unwrap() {
                            Vote::Notarize(vote) => Some(vote.proposal),
                            Vote::Finalize(vote) => Some(vote.proposal),
                            Vote::Nullify(_) => None,
                        };
                        assert_ne!(
                            proposal.map(|proposal| proposal.round),
                            Some(round),
                            "default handoff mode must not vote before parent certification"
                        );
                    },
                    _ = context.sleep(Duration::from_millis(10)) => break,
                }
            }
            verify_release_tx.send_lossy(());
        }

        assert_eq!(policies.load(Ordering::SeqCst), 1);
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert!(drop_rx.await.is_err());

        let proposal = loop {
            let (sender, message) = vote_receiver.recv().await.unwrap();
            assert_eq!(sender, victim);
            if let Vote::<S, D>::Notarize(vote) = Vote::decode(message).unwrap()
                && vote.proposal.round == round
            {
                break vote.proposal;
            }
        };
        assert_eq!(proposal, Proposal::new(round, View::new(2), digest));
        assert!(marshal.get_verified(round).await.is_some());
        let votes: Vec<_> = [0usize, 1, 2]
            .into_iter()
            .map(|i| Notarize::sign(&schemes[i], proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential).unwrap();
        certificate_sender.send(
            Recipients::One(victim),
            Certificate::<S, D>::Notarization(notarization).encode(),
            true,
        );
        loop {
            let (_, message) = vote_receiver.recv().await.unwrap();
            if let Vote::<S, D>::Finalize(vote) = Vote::decode(message).unwrap()
                && vote.proposal.round == round
            {
                assert_eq!(vote.proposal, proposal);
                break;
            }
        }
    });
}

#[test_traced("WARN")]
fn test_pipeline_handoff_retains_completed_build_until_parent_certification() {
    retained_pipeline_handoff(false);
}

#[test_traced("WARN")]
fn test_pipeline_handoff_retains_build_across_parent_certification() {
    retained_pipeline_handoff(true);
}
