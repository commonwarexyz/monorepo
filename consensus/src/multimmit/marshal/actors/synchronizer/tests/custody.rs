//! Custody lookup paging and body range-fetch tests.

use super::*;

#[test]
fn fetch_range_capacity_charges_vector_framing() {
    let exact = 16 * 100 + 16usize.encode_size();
    assert_eq!(max_block_segment_items(100, exact), 16);
    assert_eq!(max_block_segment_items(100, exact - 1), 15);
}

#[test]
fn cached_headers_backfill_only_the_missing_body_into_custody() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(23, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            3,
            digest(b"cached history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 8).await;
        for (position, block) in blocks[0].iter().enumerate() {
            actor.insert_header(block.header().clone());
            if position != 1 {
                actor
                    .catalog
                    .blocks
                    .lock()
                    .insert(block.reference(), Arc::clone(block));
            }
        }

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.catalog.block_calls.load(Ordering::Relaxed), 1);
        assert_eq!(actor.catalog.block_batches.lock().len(), 1);
        assert_eq!(
            actor
                .catalog
                .block_batches
                .lock()
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            &*actor.fetcher.block_reasons.lock(),
            &[FetchReason::FinalizedBody]
        );
        assert_eq!(actor.catalog.outputs.len(), 3);
        assert_eq!(actor.catalog.handoff, vec![blocks[0][1].reference()]);
    });
}

#[test]
fn same_chain_bodies_share_one_range_fetch() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(24, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            3,
            digest(b"parallel body history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 8).await;
        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
        }
        actor.bounds.backfill_concurrency = 3;
        actor.fetcher.yield_block_fetches = true;

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.fetcher.range_calls.load(Ordering::Relaxed), 1);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 3);
        assert_eq!(actor.fetcher.block_peak.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn interleaved_chains_form_independent_range_fetches() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(37, 3, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let bases = vec![base(0, 0), base(1, 0), base(2, 0)];
        let blocks = bases
            .iter()
            .copied()
            .map(|base| chain(epoch, base, 3))
            .collect::<Vec<_>>();
        let record = Arc::new(
            TipRecord::at_tips(
                digest(b"interleaved range history", 0),
                blocks.iter().map(|blocks| tip(blocks)).collect(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, record.parent(), bases.clone(), bases),
            blocks,
            committee.codec(),
            16,
        )
        .await;

        commit_opening(&mut actor, HistoryLink { commitment, record }).await;

        assert_eq!(actor.fetcher.range_calls.load(Ordering::Relaxed), 3);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 9);
        assert_eq!(actor.catalog.outputs.len(), 9);
    });
}

#[test]
fn local_custody_splits_a_producer_range() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(38, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            5,
            digest(b"split range history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 8).await;
        let local = Arc::clone(&blocks[0][2]);
        actor.catalog.blocks.lock().insert(local.reference(), local);

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.fetcher.range_calls.load(Ordering::Relaxed), 2);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 4);
        assert_eq!(actor.catalog.outputs.len(), 5);
    });
}

#[test]
fn short_range_prefixes_are_rescheduled() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(39, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            5,
            digest(b"short range history", 0),
        );
        let mut actor = actor(&context, current, blocks, committee.codec(), 8).await;
        actor.fetcher.range_limit = Some(2);

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.fetcher.range_calls.load(Ordering::Relaxed), 3);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 5);
        assert_eq!(actor.catalog.outputs.len(), 5);
    });
}

#[test]
fn custody_lookup_pages_are_bounded_by_the_resolved_artifact_limit() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(31, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            40,
            digest(b"custody page history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 64).await;
        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
            actor
                .catalog
                .blocks
                .lock()
                .insert(block.reference(), Arc::clone(block));
        }

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.bounds.custody_batch_outputs, 16);
        assert_eq!(
            actor
                .catalog
                .block_batches
                .lock()
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![16, 16, 8]
        );
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn custody_window_matches_backfill_response_capacity() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(41, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let actor = actor(
            &context,
            checkpoint(
                epoch,
                digest(b"custody window capacity", 0),
                vec![base],
                vec![base],
            ),
            vec![Vec::new()],
            committee.codec(),
            64,
        )
        .await;

        assert_eq!(actor.bounds.custody_batch_outputs, 16);
        assert_eq!(actor.bounds.backfill_concurrency, 32);
        assert_eq!(actor.bounds.max_fetch_blocks, 15);
        assert_eq!(
            actor.bounds.custody_window_outputs,
            actor.bounds.backfill_concurrency * actor.bounds.max_fetch_blocks
        );
    });
}

#[test]
fn small_custody_window_still_schedules_a_lookup_page() {
    deterministic::Runner::default().start(|context| async move {
        const OUTPUTS: usize = 40;
        let committee = committee(42, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            OUTPUTS,
            digest(b"small custody window", 0),
        );
        let mut actor =
            actor_with_backfill(&context, current, blocks.clone(), committee.codec(), 64, 1).await;
        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
        }

        assert_eq!(actor.bounds.custody_window_outputs, 15);
        assert_eq!(actor.bounds.custody_batch_outputs, 15);
        commit_opening(&mut actor, opening).await;
        assert_eq!(actor.catalog.outputs.len(), OUTPUTS);
    });
}

#[rstest]
#[case(false)]
#[case(true)]
fn custody_window_schedules_past_a_blocked_first_page(#[case] known: bool) {
    deterministic::Runner::default().start(|context| async move {
        const OUTPUTS: usize = 40;
        const PAGE: usize = 16;
        let committee = committee(33, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            OUTPUTS,
            digest(b"custody window history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 64).await;
        if known {
            actor.commitments.insert(&selected(actor.epoch, &blocks));
        }

        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
        }
        actor.bounds.backfill_concurrency = 32;
        actor.fetcher.fetch_requires = Some((blocks[0][0].reference(), PAGE + 1));

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.catalog.outputs.len(), OUTPUTS);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), OUTPUTS);
    });
}

#[rstest]
#[case(false)]
#[case(true)]
fn custody_window_refills_past_a_blocked_trailing_page(#[case] known: bool) {
    deterministic::Runner::default().start(|context| async move {
        const OUTPUTS: usize = 64;
        const PAGE: usize = 16;
        const WINDOW: usize = PAGE * COMMIT_WINDOW;
        let committee = committee(34, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            OUTPUTS,
            digest(b"sliding custody history", 0),
        );
        let mut actor = actor(
            &context,
            current,
            blocks.clone(),
            committee.codec(),
            OUTPUTS,
        )
        .await;
        if known {
            actor.commitments.insert(&selected(actor.epoch, &blocks));
        }

        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
        }
        actor.bounds.backfill_concurrency = WINDOW;
        actor.fetcher.fetch_requires = Some((blocks[0][WINDOW - 1].reference(), WINDOW + 1));

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.catalog.outputs.len(), OUTPUTS);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), OUTPUTS);
    });
}

#[rstest]
#[case(false)]
#[case(true)]
fn custody_window_refills_keep_page_batches(#[case] known: bool) {
    deterministic::Runner::default().start(|context| async move {
        const OUTPUTS: usize = 64;
        const PAGE: usize = 16;
        let committee = committee(35, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            OUTPUTS,
            digest(b"batched custody refill history", 0),
        );
        let mut actor = actor(
            &context,
            current,
            blocks.clone(),
            committee.codec(),
            OUTPUTS,
        )
        .await;
        if known {
            actor.commitments.insert(&selected(actor.epoch, &blocks));
        }

        for block in &blocks[0] {
            actor.insert_header(block.header().clone());
        }
        actor.bounds.backfill_concurrency = PAGE * COMMIT_WINDOW;
        actor.fetcher.fetch_delay_by_height = true;

        commit_opening(&mut actor, opening).await;

        assert_eq!(
            actor
                .catalog
                .block_batches
                .lock()
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![PAGE; OUTPUTS / PAGE]
        );
    });
}

/// Returns the slots of one opening from `base` to the tip of `blocks`.
fn opening_slots(
    blocks: &[Arc<TestBlock>],
    base: BlockRef<Sha256Digest>,
) -> Vec<Slot<Sha256Digest>> {
    let tip = tip(blocks);
    SlotStream::new(&[base], &[tip], &[tip.height()])
        .unwrap()
        .collect()
}

/// Returns a window over `blocks`, with the ordering stream exhausted.
fn filled_window(
    epoch: Epoch,
    blocks: &[Arc<TestBlock>],
    batch: usize,
    max_fetch: usize,
) -> CustodyWindow<Sha256, TestBody> {
    let mut window = CustodyWindow::new(
        epoch,
        WindowBounds {
            capacity: blocks.len(),
            batch,
            max_fetch,
            max_fetches: 1,
        },
    );
    for (slot, block) in opening_slots(blocks, base(0, 0)).into_iter().zip(blocks) {
        assert!(window.has_room());
        window.push(slot, block.reference()).unwrap();
    }
    window.finish();
    assert!(!window.has_room());
    window
}

/// Returns the custody the catalog holds for `references` among `held`.
fn held_custody(
    held: &[Arc<TestBlock>],
    references: &[BlockRef<Sha256Digest>],
) -> CustodyValues<Sha256Digest> {
    references
        .iter()
        .map(|reference| {
            held.iter()
                .find(|block| block.reference() == *reference)
                .map(CustodyRef::for_test)
        })
        .collect()
}

/// Returns `references` from `blocks` with their custody, truncated to `limit`.
fn fetched_prefix(
    blocks: &[Arc<TestBlock>],
    references: &[BlockRef<Sha256Digest>],
    limit: usize,
) -> Vec<CustodiedBlock<Sha256, TestBody>> {
    references
        .iter()
        .take(limit)
        .map(|reference| {
            let block = blocks
                .iter()
                .find(|block| block.reference() == *reference)
                .cloned()
                .unwrap();
            CustodiedBlock::new(CustodyRef::for_test(&block), block).unwrap()
        })
        .collect()
}

async fn complete_lookups(window: &mut CustodyWindow<Sha256, TestBody>) -> usize {
    let mut resolved = 0;
    while window.lookups() > 0 {
        let Completion::Lookup(lookup) = window.next_completion().await else {
            panic!("a fetch completed while only lookups were in flight");
        };
        resolved += window.on_lookup(lookup).unwrap();
    }
    resolved
}

async fn complete_fetch(window: &mut CustodyWindow<Sha256, TestBody>) -> usize {
    let Completion::Fetch(fetch) = window.next_completion().await else {
        panic!("a lookup completed while only a fetch was in flight");
    };
    window.on_fetch(fetch).unwrap()
}

#[test]
fn custody_window_releases_only_its_resolved_prefix() {
    deterministic::Runner::default().start(|_| async move {
        let epoch = Epoch::new(3);
        let blocks = chain(epoch, base(0, 0), 3);
        let mut window = filled_window(epoch, &blocks, 2, 2);
        let held = [Arc::clone(&blocks[0]), Arc::clone(&blocks[2])];

        let mut pages = Vec::new();
        window
            .schedule_lookups(|references| {
                pages.push(references.len());
                futures::future::ready(Ok(held_custody(&held, &references)))
            })
            .unwrap();
        assert_eq!(pages, vec![2, 1]);
        assert_eq!(complete_lookups(&mut window).await, 2);

        let first = window.pop_ready().unwrap();
        assert_eq!(first.custody.reference(), blocks[0].reference());
        assert!(first.block.is_none());
        assert!(
            window.pop_ready().is_none(),
            "an unresolved output released its successor"
        );
        assert!(window.block());
        assert!(!window.block());
        assert!(!window.is_stalled());

        let mut requested = Vec::new();
        window.schedule_fetches(|references| {
            requested.push(references.clone());
            futures::future::ready(Ok(fetched_prefix(&blocks, &references, usize::MAX)))
        });
        assert_eq!(requested, vec![vec![blocks[1].reference()]]);
        assert_eq!(complete_fetch(&mut window).await, 1);

        let released = std::iter::from_fn(|| window.pop_ready()).collect::<Vec<_>>();
        assert_eq!(
            released
                .iter()
                .map(|output| output.custody.reference())
                .collect::<Vec<_>>(),
            vec![blocks[1].reference(), blocks[2].reference()]
        );
        assert!(released[0].block.is_some());
        assert!(released[1].block.is_none());
        assert!(window.is_done());
    });
}

#[test]
fn custody_window_refetches_the_rest_of_a_short_run() {
    deterministic::Runner::default().start(|_| async move {
        let epoch = Epoch::new(3);
        let blocks = chain(epoch, base(0, 0), 3);
        let mut window = filled_window(epoch, &blocks, 3, 3);
        window
            .schedule_lookups(|references| {
                futures::future::ready(Ok(held_custody(&[], &references)))
            })
            .unwrap();
        assert_eq!(complete_lookups(&mut window).await, 0);

        let mut requested = Vec::new();
        window.schedule_fetches(|references| {
            requested.push(references.clone());
            futures::future::ready(Ok(fetched_prefix(&blocks, &references, 1)))
        });
        assert_eq!(complete_fetch(&mut window).await, 1);
        assert!(window.pop_ready().is_none());

        window.schedule_fetches(|references| {
            requested.push(references.clone());
            futures::future::ready(Ok(fetched_prefix(&blocks, &references, usize::MAX)))
        });
        assert_eq!(complete_fetch(&mut window).await, 2);
        let newest_first = |heights: &[usize]| {
            heights
                .iter()
                .map(|height| blocks[*height].reference())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            requested,
            vec![newest_first(&[2, 1, 0]), newest_first(&[1, 0])]
        );
        assert_eq!(std::iter::from_fn(|| window.pop_ready()).count(), 3);
        assert!(window.is_done());
    });
}

#[test]
fn custody_window_rejects_a_lookup_of_the_wrong_cardinality() {
    deterministic::Runner::default().start(|_| async move {
        let epoch = Epoch::new(3);
        let blocks = chain(epoch, base(0, 0), 2);
        let mut window = filled_window(epoch, &blocks, 2, 2);
        window
            .schedule_lookups(|references| {
                futures::future::ready(Ok(held_custody(&blocks, &references[..1])))
            })
            .unwrap();
        let Completion::Lookup(lookup) = window.next_completion().await else {
            panic!("a fetch completed before any was scheduled");
        };

        assert!(matches!(
            window.on_lookup(lookup),
            Err(Error::Invalid("catalog block batch cardinality mismatch"))
        ));
    });
}
