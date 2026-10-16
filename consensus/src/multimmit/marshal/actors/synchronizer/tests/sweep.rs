//! Resolution and open-view sweep tests: Horiz per resolved view, gap repair, and the sweep
//! prefix.

use super::*;

/// Two chains above genesis: three blocks on chain 0 and two on chain 1.
struct Views {
    committee: Committee<MinPk>,
    blocks: Vec<Vec<Arc<TestBlock>>>,
}

impl Views {
    fn new(seed: u64) -> Self {
        let committee = committee(seed, 2);
        let epoch = committee.config.epoch();
        let tips = committee.config.genesis().tips().to_vec();
        let blocks = vec![chain(epoch, tips[0], 3), chain(epoch, tips[1], 2)];
        Self { committee, blocks }
    }

    /// Returns the block at `height` on `chain`, or the genesis tip at height zero.
    fn at(&self, chain: usize, height: u64) -> BlockRef<Sha256Digest> {
        match height {
            0 => self.committee.config.genesis().tips()[chain],
            height => self.blocks[chain][height as usize - 1].reference(),
        }
    }

    fn tips(&self, heights: [u64; 2]) -> Vec<BlockRef<Sha256Digest>> {
        vec![self.at(0, heights[0]), self.at(1, heights[1])]
    }

    /// Returns the openings of consecutive views from genesis, one per tip-height pair.
    fn records(&self, heights: &[[u64; 2]]) -> Vec<Arc<HistoryRecord<Sha256Digest>>> {
        let mut parent = self.committee.config.genesis().history();
        heights
            .iter()
            .map(|heights| {
                let record = Arc::new(HistoryRecord::new(parent, self.tips(*heights)).unwrap());
                parent = record.commitment::<Sha256>();
                record
            })
            .collect()
    }

    /// Returns the outputs of `points`, given as `(chain, height)`.
    fn outputs(&self, points: &[(usize, u64)]) -> Vec<BlockRef<Sha256Digest>> {
        points
            .iter()
            .map(|(chain, height)| self.at(*chain, *height))
            .collect()
    }

    async fn actor(&self, context: &deterministic::Context) -> TestSynchronizer {
        let genesis = self.committee.config.genesis();
        self.actor_at(context, genesis.tips().to_vec()).await
    }

    /// Returns a synchronizer at genesis whose emitted frontier is `emitted`.
    async fn actor_at(
        &self,
        context: &deterministic::Context,
        emitted: Vec<BlockRef<Sha256Digest>>,
    ) -> TestSynchronizer {
        let genesis = self.committee.config.genesis();
        actor(
            context,
            checkpoint(
                self.committee.config.epoch(),
                0,
                genesis.history(),
                genesis.tips().to_vec(),
                emitted,
            ),
            self.blocks.clone(),
            self.committee.codec(),
            8,
        )
        .await
    }
}

fn resolved(view: u64, record: &Arc<HistoryRecord<Sha256Digest>>) -> Target<MinPk, Sha256Digest> {
    Target::resolved(
        View::new(view),
        record.commitment::<Sha256>(),
        Arc::clone(record),
        2,
    )
}

fn settled(members: &[u32]) -> ChainSet {
    ChainSet::from_chains(2, members.iter().copied().map(ChainId::new)).unwrap()
}

#[test]
fn resolution_emits_the_horizontal_order_without_fetching_history() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(40);
        let records = views.records(&[[3, 2]]);
        let mut actor = views.actor(&context).await;

        actor
            .synchronize_target(resolved(1, &records[0]))
            .await
            .unwrap();

        assert_eq!(
            actor.catalog.outputs,
            views.outputs(&[(0, 1), (1, 1), (0, 2), (1, 2), (0, 3)])
        );
        assert_eq!(actor.fetcher.history_calls.load(Ordering::Relaxed), 0);
        assert_eq!(actor.catalog.history_commits, 1);
        assert_eq!(actor.state.view(), View::new(1));
        assert_eq!(actor.state.history(), records[0].commitment::<Sha256>());
        assert_eq!(actor.committed, OutputIndex::new(5));
    });
}

#[test]
fn gap_repair_opens_every_missed_view_in_order() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(41);
        let records = views.records(&[[1, 0], [1, 2], [3, 2]]);
        let mut actor = views.actor(&context).await;
        actor.fetcher.histories = records[..2]
            .iter()
            .map(|record| (record.commitment::<Sha256>(), Arc::clone(record)))
            .collect();

        actor
            .synchronize_target(resolved(3, &records[2]))
            .await
            .unwrap();

        assert_eq!(
            actor.catalog.outputs,
            views.outputs(&[(0, 1), (1, 1), (1, 2), (0, 2), (0, 3)])
        );
        assert_eq!(actor.catalog.history_commits, 3);
        assert_eq!(actor.state.view(), View::new(3));

        // A target at the synchronized view must name its history; one below it is stale.
        actor
            .synchronize_target(resolved(3, &records[2]))
            .await
            .unwrap();
        actor
            .synchronize_target(resolved(2, &records[1]))
            .await
            .unwrap();
        assert!(matches!(
            actor.synchronize_target(resolved(3, &records[1])).await,
            Err(Error::Invalid(_))
        ));
        assert_eq!(actor.catalog.outputs.len(), 5);
    });
}

#[test]
fn history_chains_must_reach_the_synchronized_view_exactly() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(42);
        let records = views.records(&[[1, 0], [1, 1]]);

        // The chain reaches genesis after two records, but the target claims view three.
        let mut actor = views.actor(&context).await;
        actor.fetcher.histories =
            vec![(records[0].commitment::<Sha256>(), Arc::clone(&records[0]))];
        assert!(matches!(
            actor.synchronize_target(resolved(3, &records[1])).await,
            Err(Error::Invalid(
                "tips-history chain does not match its resolved views"
            ))
        ));

        // The chain passes the synchronized view without reaching its history.
        let mut actor = views.actor(&context).await;
        let unrelated = Arc::new(
            HistoryRecord::new(digest(b"unrelated parent", 0), views.tips([1, 0])).unwrap(),
        );
        assert!(matches!(
            actor.synchronize_target(resolved(1, &unrelated)).await,
            Err(Error::Invalid(
                "tips-history chain passes the synchronized view"
            ))
        ));
        assert_eq!(actor.fetcher.history_calls.load(Ordering::Relaxed), 0);
        assert!(actor.catalog.outputs.is_empty());
    });
}

#[test]
fn sweep_emits_a_prefix_that_the_resolution_continues() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(43);
        let records = views.records(&[[3, 2]]);
        let mut actor = views.actor(&context).await;

        // Chain 1 is unsettled above its final tip at height 2, which halts the sweep.
        actor
            .retain_sweep(View::new(1), views.tips([2, 1]).into(), settled(&[]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert_eq!(
            actor.catalog.outputs,
            views.outputs(&[(0, 1), (1, 1), (0, 2)])
        );
        assert_eq!(actor.state.view(), View::zero());
        assert_eq!(actor.state.emitted(), views.tips([2, 1]).as_slice());
        assert_eq!(actor.metrics.sweeps.get(), 1);

        // A repeated report emits nothing more.
        actor
            .retain_sweep(View::new(1), views.tips([2, 1]).into(), settled(&[]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert_eq!(actor.catalog.outputs.len(), 3);

        actor
            .synchronize_target(resolved(1, &records[0]))
            .await
            .unwrap();
        assert_eq!(
            actor.catalog.outputs,
            views.outputs(&[(0, 1), (1, 1), (0, 2), (1, 2), (0, 3)])
        );
        assert_eq!(actor.committed, OutputIndex::new(5));

        // The resolved view's sweep is dropped.
        actor.synchronize_sweep().await.unwrap();
        assert!(actor.sweep.is_none());
    });
}

#[test]
fn sweep_skips_settled_chains_and_waits_for_its_base() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(44);
        let records = views.records(&[[1, 1]]);
        let mut actor = views.actor(&context).await;

        // The sweep of view 2 waits until view 1 resolves.
        actor
            .retain_sweep(View::new(2), views.tips([3, 1]).into(), settled(&[1]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert!(actor.catalog.outputs.is_empty());

        // A sweep of an earlier view than the retained one is stale.
        actor
            .retain_sweep(View::new(1), views.tips([1, 1]).into(), settled(&[]))
            .unwrap();
        assert_eq!(
            actor.sweep.as_ref().map(|sweep| sweep.view),
            Some(View::new(2))
        );

        actor
            .synchronize_target(resolved(1, &records[0]))
            .await
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        // Chain 1 is settled at its base, so chain 0 continues past it.
        assert_eq!(
            actor.catalog.outputs,
            views.outputs(&[(0, 1), (1, 1), (0, 2), (0, 3)])
        );
    });
}

#[test]
fn sweep_retreat_within_a_view_fails_closed() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(45);
        let mut actor = views.actor(&context).await;
        actor
            .retain_sweep(View::new(1), views.tips([2, 1]).into(), settled(&[1]))
            .unwrap();
        assert!(matches!(
            actor.retain_sweep(View::new(1), views.tips([1, 1]).into(), settled(&[1])),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            actor.retain_sweep(View::new(1), views.tips([2, 1]).into(), settled(&[])),
            Err(Error::Invalid(_))
        ));
        // Another block at a retained final height conflicts with it.
        let mut conflicting = views.tips([2, 1]);
        conflicting[0] = BlockRef::new(
            conflicting[0].chain(),
            conflicting[0].height(),
            digest(b"conflicting final", 2),
        );
        assert!(matches!(
            actor.retain_sweep(View::new(1), conflicting.into(), settled(&[1])),
            Err(Error::Invalid("sweep retreats within its view"))
        ));
        // Rising final tips and newly settled chains are progress.
        actor
            .retain_sweep(View::new(1), views.tips([3, 1]).into(), settled(&[0, 1]))
            .unwrap();

        // A sweep that is not one tip per chain fails its order.
        let mut actor = views.actor(&context).await;
        actor
            .retain_sweep(View::new(1), views.tips([2, 1])[..1].into(), settled(&[1]))
            .unwrap();
        assert!(matches!(
            actor.synchronize_sweep().await,
            Err(Error::Order(order::Error::Algebra(_)))
        ));
    });
}

#[test]
fn sweep_below_the_emitted_prefix_is_stale() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(46);
        // An earlier process emitted (0, 1), (1, 1), (0, 2) from a sweep of view 1.
        let mut actor = views.actor_at(&context, views.tips([2, 1])).await;

        actor
            .retain_sweep(View::new(1), views.tips([1, 1]).into(), settled(&[]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert!(actor.catalog.outputs.is_empty());
        assert_eq!(actor.metrics.stale_sweeps.get(), 1);

        // A sweep covering the prefix continues it.
        actor
            .retain_sweep(View::new(1), views.tips([3, 1]).into(), settled(&[1]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert_eq!(actor.catalog.outputs, views.outputs(&[(0, 3)]));
    });
}

#[test]
fn resolution_contradicting_the_swept_prefix_fails_closed() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(47);
        let records = views.records(&[[2, 1]]);
        let mut actor = views.actor(&context).await;
        // Chain 1 was settled at genesis, so the sweep placed (0, 2) before any chain 1 block.
        actor
            .retain_sweep(View::new(1), views.tips([2, 0]).into(), settled(&[1]))
            .unwrap();
        actor.synchronize_sweep().await.unwrap();
        assert_eq!(actor.catalog.outputs, views.outputs(&[(0, 1), (0, 2)]));

        assert!(matches!(
            actor.synchronize_target(resolved(1, &records[0])).await,
            Err(Error::Order(order::Error::Prefix))
        ));
        assert_eq!(actor.catalog.outputs.len(), 2);
    });
}

#[test]
fn sweep_final_tips_off_the_emitted_path_fail_closed() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(48);
        let epoch = views.committee.config.epoch();
        let genesis = views.committee.config.genesis().tips().to_vec();
        let rival = branch(epoch, genesis[0], 2, b"rival");
        let mut actor = views.actor_at(&context, views.tips([1, 0])).await;
        let mut blocks = views.blocks.clone();
        blocks[0].extend(rival.iter().cloned());
        actor.fetcher.blocks = Arc::new(blocks);

        actor
            .retain_sweep(
                View::new(1),
                vec![tip(&rival), genesis[1]].into(),
                settled(&[1]),
            )
            .unwrap();
        assert!(matches!(
            actor.synchronize_sweep().await,
            Err(Error::Order(order::Error::Conflict))
        ));
        assert!(actor.catalog.outputs.is_empty());
    });
}

#[test]
fn lqcs_pinning_earlier_views_survive_higher_targets() {
    deterministic::Runner::default().start(|context| async move {
        let views = Views::new(49);
        let quorum = 0..views.committee.codec().view_quorum();
        let records = views.records(&[[1, 0], [1, 1], [2, 1]]);
        let pinning = |view: usize, signers| {
            lqc(
                &views.committee,
                view as u64 + 1,
                records[view - 1].commitment::<Sha256>(),
                signers,
            )
        };
        let first = pinning(1, quorum.clone());
        let second = pinning(2, quorum.clone());
        let mut actor = views.actor(&context).await;
        actor.fetcher.histories = records[..2]
            .iter()
            .map(|record| (record.commitment::<Sha256>(), Arc::clone(record)))
            .collect();

        // A resolution of a later view merges over both L-QCs, which pin the views it opens.
        let mut target = Target::finalized(first.id::<Sha256>(), Arc::clone(&first), None, 4);
        target.merge(Target::finalized(
            second.id::<Sha256>(),
            Arc::clone(&second),
            None,
            4,
        ));
        target.merge(resolved(3, &records[2]));
        actor.synchronize_target(target).await.unwrap();
        assert_eq!(
            actor.catalog.selected,
            vec![first.id::<Sha256>(), second.id::<Sha256>()]
        );
        assert_eq!(actor.floor, second.id::<Sha256>());
        assert_eq!(actor.state.view(), View::new(3));

        // An L-QC pinning a view the order already passed is not selected.
        let late = pinning(2, 1..views.committee.codec().view_quorum() + 1);
        actor
            .synchronize_target(Target::finalized(late.id::<Sha256>(), late, None, 2))
            .await
            .unwrap();
        assert_eq!(actor.catalog.selected.len(), 2);
    });
}
