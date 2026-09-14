use super::*;
use crate::marshal::ancestry::Ancestry;

#[derive(Clone)]
struct PipelineApp {
    verify_started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    verify_release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    build_started: Arc<Mutex<Option<oneshot::Sender<Ctx>>>>,
    build_dropped: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    replacement: Arc<Mutex<Option<oneshot::Sender<Ctx>>>>,
    policies: Arc<AtomicUsize>,
    block: B,
}

struct Dropped(Option<oneshot::Sender<()>>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.take().unwrap().send_lossy(());
    }
}

impl crate::Application<Runtime> for PipelineApp {
    type Block = B;
    type Context = Ctx;
    type SigningScheme = S;
    type Input = ();

    async fn handoff_policy(&mut self, _: (Runtime, Ctx)) -> HandoffPolicy {
        self.policies.fetch_add(1, Ordering::SeqCst);
        HandoffPolicy::Pipeline
    }

    async fn propose(
        &mut self,
        (_, context): (Runtime, Ctx),
        _: impl Ancestry<B>,
        _: (),
    ) -> Option<B> {
        let started = self.build_started.lock().take();
        if let Some(started) = started {
            let _dropped = Dropped(self.build_dropped.lock().take());
            started.send_lossy(context);
            std::future::pending::<()>().await;
            unreachable!();
        }
        self.replacement.lock().take().unwrap().send_lossy(context);
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

#[test_traced("WARN")]
fn test_deferred_pipeline_build_replaced_after_parent_certification() {
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
        let (release_tx, release_rx) = oneshot::channel();
        let (build_tx, build_rx) = oneshot::channel();
        let (drop_tx, drop_rx) = oneshot::channel();
        let (replacement_tx, replacement_rx) = oneshot::channel();
        let policies = Arc::new(AtomicUsize::new(0));
        let app = PipelineApp {
            verify_started: Arc::new(Mutex::new(Some(verify_tx))),
            verify_release: Arc::new(Mutex::new(Some(release_rx))),
            build_started: Arc::new(Mutex::new(Some(build_tx))),
            build_dropped: Arc::new(Mutex::new(Some(drop_tx))),
            replacement: Arc::new(Mutex::new(Some(replacement_tx))),
            policies: policies.clone(),
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
                reporter: marshal,
                strategy: Sequential,
                partition: "pipeline-replacement".into(),
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
            },
        );
        let _engine = engine.start(vote_network, certificate_network, resolver_network);
        // Register the real verification gate before delivering its notarization.
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

        // Certification releases the handoff while Application::propose is pending.
        release_tx.send_lossy(());
        select! {
            result = drop_rx => result.expect("cancelled application build must be dropped"),
            _ = context.sleep(Duration::from_secs(5)) => panic!("cancelled application build was retained"),
        }
        assert_eq!(replacement_rx.await.unwrap(), expected_context);
        assert_eq!(
            policies.load(Ordering::SeqCst),
            1,
            "replacement must be ordinary"
        );
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
