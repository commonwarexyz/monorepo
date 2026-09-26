//! Body, header, and output reads, the caches that serve them, and materialization.

use super::*;
use crate::multimmit::testing::expect_within;

#[test]
fn pending_metadata_bypasses_finalized_archive_reads() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(52, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_PENDING_METADATA")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..4)
            .map(|chain| producer_block(&committee, chain, 52 + u64::from(chain)))
            .collect::<Vec<_>>();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            config.capacities.max_commit_outputs = NZUsize!(4);
            config.archive.page_cache = CacheRef::from_pooler(context, NZU16!(1), NZUsize!(1));
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, &blocks))
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), delayed.child("reopened")).await;
        let reference = blocks[0].reference();
        let gate = reads.arm();
        let mut pending = Box::pin(async {
            let (custody, headers) = futures::try_join!(
                client.wait_for_custody(vec![reference]),
                client.header_segments(vec![(reference, 1)], usize::MAX),
            )?;
            Ok::<_, Error>((custody, headers))
        });
        let (custody, headers) = commonware_macros::select! {
            result = &mut pending => result.unwrap(),
            result = gate.blocked => {
                result.unwrap();
                panic!("pending metadata lookup reached finalized storage")
            },
        };
        assert!(custody[0].is_some());
        assert_eq!(headers[0], vec![blocks[0].header().clone()]);

        drop(pending);
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn header_batch_capacity_is_independent_of_admission_cut() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(57, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HEADER_CAPACITY")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..4)
            .map(|chain| producer_block(&committee, chain, 57 + u64::from(chain)))
            .collect::<Vec<_>>();
        let mut config = config(&context, &committee);
        set_capacity(&mut config, 1);
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }

        let headers = client
            .header_segments(
                blocks.iter().map(|block| (block.reference(), 1)).collect(),
                usize::MAX,
            )
            .await
            .unwrap();
        assert_eq!(headers.len(), blocks.len());
        for (headers, block) in headers.iter().zip(&blocks) {
            assert_eq!(headers, std::slice::from_ref(block.header()));
        }

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn finalized_header_branches_follow_parents() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(58, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HEADER_BRANCHES")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let parents = (0..2)
            .map(|chain| producer_block(&committee, chain, 58 + u64::from(chain)))
            .collect::<Vec<_>>();
        let children = parents
            .iter()
            .enumerate()
            .map(|(chain, parent)| {
                let body = TestBody::new(
                    Sha256::hash(&[b"application parent"]),
                    Height::new(10),
                    60 + chain as u64,
                );
                let header = TransactionBlockHeader::new(
                    committee.config.epoch(),
                    ChainId::new(chain as u32),
                    Height::new(2),
                    parent.reference().digest(),
                    body.digest(),
                )
                .unwrap();
                Arc::new(TransactionBlock::new(header, body).unwrap())
            })
            .collect::<Vec<_>>();
        let blocks = parents.iter().chain(&children).cloned().collect::<Vec<_>>();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            config.capacities.max_commit_outputs = NZUsize!(4);
            config.retention.blocks = ArchiveMode::Immutable;
            config
        };

        let (client, handle, promoter, _delivery) =
            spawn_catalog_with_promoter(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        let current = client.checkpoint().await.unwrap();
        let mut emitted = current.emitted().to_vec();
        for block in &children {
            emitted[block.reference().chain().get() as usize] = block.reference();
        }
        client
            .commit(Commit {
                selected: Vec::new(),
                history: Vec::new(),
                outputs: blocks
                    .iter()
                    .enumerate()
                    .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                    .collect(),
                checkpoint: Checkpoint::try_from(CheckpointParts {
                    epoch: current.epoch(),
                    floor_generation: current.floor_generation(),
                    archive_layout: current.archive_layout(),
                    floor: current.floor(),
                    history: current.history(),
                    history_index: current.history_index(),
                    ordered: current.ordered().to_vec(),
                    emitted: emitted.clone(),
                    committed: Some(OutputIndex::new(3)),
                })
                .unwrap(),
            })
            .await
            .unwrap();
        client.promoted(emitted).await.unwrap();
        drop(client);
        handle.abort();
        let _ = handle.await;
        // The promoter owns the immutable body archive; stop it so reopening can claim it.
        let promoter = promoter.expect("immutable finalized blocks run a promoter");
        promoter.abort();
        let _ = promoter.await;

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("reopened")).await;
        let headers = client
            .header_segments(
                children
                    .iter()
                    .map(|block| (block.reference(), 2))
                    .collect(),
                usize::MAX,
            )
            .await
            .unwrap();
        for ((headers, child), parent) in headers.iter().zip(&children).zip(&parents) {
            assert_eq!(headers, &[child.header().clone(), parent.header().clone()]);
        }

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[test]
fn historical_body_reads_do_not_displace_live_custody() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_CACHE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 40);
        let second = producer_block(&committee, 0, 41);
        let absent = producer_block(&committee, 0, 42);
        let mut config = config(&context, &committee);
        config.limits.max_hot_block_bytes =
            NonZeroUsize::new(first.encode_size()).expect("the block is non-empty");
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
        client
            .admit_block(first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        client
            .admit_block(second.reference(), Arc::clone(&second))
            .await
            .unwrap();

        let materialized_before = metric_total(&context.encode(), "materialized_bodies_total");
        assert_eq!(
            client.bodies(vec![first.reference()]).await.unwrap()[0].as_deref(),
            Some(first.as_ref())
        );
        let materialized_after = metric_total(&context.encode(), "materialized_bodies_total");
        assert!(materialized_after > materialized_before);

        assert_eq!(
            client.bodies(vec![first.reference()]).await.unwrap()[0].as_deref(),
            Some(first.as_ref())
        );
        assert_eq!(
            metric_total(&context.encode(), "materialized_bodies_total"),
            materialized_after
        );

        let custody = client
            .wait_for_custody(vec![
                second.reference(),
                first.reference(),
                absent.reference(),
            ])
            .await
            .unwrap();
        assert!(custody[0].is_some());
        assert!(custody[1].is_some());
        assert!(custody[2].is_none());
        let metrics = context.encode();
        assert_eq!(metric_total(&metrics, "custody_cache_hits_total"), 1);
        assert_eq!(metric_total(&metrics, "custody_storage_hits_total"), 1);
        assert_eq!(metric_total(&metrics, "custody_misses_total"), 1);
        assert_eq!(metric_total(&metrics, "block_cache_evictions_total"), 1);
        assert_eq!(metric_total(&metrics, "block_cache_items"), 1);
        assert_eq!(
            metric_total(&metrics, "block_cache_bytes"),
            u64::try_from(second.encode_size()).unwrap()
        );
        assert_eq!(metric_total(&metrics, "materialized_cache_items"), 1);
        assert_eq!(
            metric_total(&metrics, "materialized_cache_bytes"),
            u64::try_from(first.encode_size()).unwrap()
        );

        assert_eq!(
            client.bodies(vec![second.reference()]).await.unwrap()[0].as_deref(),
            Some(second.as_ref())
        );
        let materialized_live = metric_total(&context.encode(), "materialized_bodies_total");
        assert_eq!(materialized_live, materialized_after);

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[derive(Clone, Copy)]
enum IndependentReadCase {
    Body,
    Candidate,
    Headers,
    Outputs,
}

#[rstest::rstest]
#[case::body(false, IndependentReadCase::Body)]
#[case::full_body(true, IndependentReadCase::Body)]
#[case::candidate(false, IndependentReadCase::Candidate)]
#[case::headers(false, IndependentReadCase::Headers)]
#[case::outputs(false, IndependentReadCase::Outputs)]
fn independent_read_completes_during_segment_open(
    #[case] full: bool,
    #[case] read_case: IndependentReadCase,
) {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(81, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_DURING_APPEND")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let configure = || {
            let mut config = config(&context, &committee);
            set_capacity(&mut config, 1);
            config
        };
        let first = producer_block(&committee, 0, 81);
        let next = producer_block(&committee, 1, 82);
        let (client, handle, _delivery) =
            spawn_catalog(configure(), context.child("initial")).await;
        client
            .admit_block(first.reference(), first.clone())
            .await
            .unwrap();
        if full {
            let tail = producer_block(&committee, 2, 83);
            client.admit_block(tail.reference(), tail).await.unwrap();
        }
        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, [&first]))
            .await
            .unwrap();
        let refs = client
            .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024))
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let opens = Gates::default();
        let delayed = DelayedOpenContext {
            inner: context.child("delayed"),
            pending: opens.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(), delayed.child("reopened")).await;
        let gate = opens.arm();
        let mut admission = Box::pin(client.stage_block(next));
        select! {
            _ = &mut admission => panic!("append completed before opening its segment"),
            result = gate.blocked => result.unwrap(),
            _ = context.sleep(std::time::Duration::from_millis(100)) => {
                panic!("new segment did not reach storage");
            },
        }
        let mut ordinary = Box::pin(client.block(first.reference()));
        select! {
            _ = &mut ordinary => panic!("ordinary read overtook the admission"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        let bodies = Bodies::new(client.clone(), None);
        let mut read = Box::pin(async {
            match read_case {
                IndependentReadCase::Body => {
                    assert_eq!(
                        bodies.materialize(&refs).await.unwrap()[0].as_ref(),
                        first.as_ref()
                    );
                }
                IndependentReadCase::Candidate => {
                    let candidate = client
                        .read(|reply| Read::BodyCandidate {
                            chain: first.reference().chain(),
                            digest: first.reference().digest(),
                            reply,
                        })
                        .await
                        .unwrap()
                        .expect("the stored block has a candidate");
                    assert_eq!(candidate.0, first.reference());
                }
                IndependentReadCase::Headers => {
                    let headers = client
                        .header_segments(vec![(first.reference(), 1)], 1024)
                        .await
                        .unwrap();
                    assert_eq!(headers, vec![vec![first.header().clone()]]);
                }
                IndependentReadCase::Outputs => {
                    let outputs = client
                        .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024))
                        .await
                        .unwrap();
                    assert_eq!(outputs[0].reference, first.reference());
                }
            }
        });
        expect_within(
            &context,
            std::time::Duration::from_millis(10),
            &mut read,
            "independent catalog read waited for unrelated segment-open I/O",
        )
        .await;
        assert_eq!(
            metric_total(&context.encode(), "materialized_bodies_total"),
            u64::from(matches!(read_case, IndependentReadCase::Body))
        );
        gate.release.send(()).unwrap();
        admission.await.unwrap().wait().await.unwrap();
        assert_eq!(ordinary.await.unwrap().as_deref(), Some(first.as_ref()));
        drop(read);
        drop(bodies);
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn body_reads_wait_for_materialization_capacity() {
    let paths = SpanPaths::default();
    let subscriber = tracing_subscriber::registry().with(paths.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(44, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_BACKPRESSURE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 44);
        let second = producer_block(&committee, 1, 45);
        let evictor = producer_block(&committee, 2, 46);
        let mut initial = config(&context, &committee);
        set_capacity(&mut initial, 1);
        initial.limits.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
        let (client, handle, _delivery) =
            spawn_catalog(initial, context.child("initial")).await;
        for block in [&first, &second, &evictor] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut reopened = config(&context, &committee);
        set_capacity(&mut reopened, 1);
        reopened.limits.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
        let (client, handle, _delivery) =
            spawn_catalog(reopened, delayed.child("catalog")).await;

        let gate = reads.arm();
        let mut first_read = Box::pin(
            client.block(first.reference()).instrument(info_span!("test.first_request")),
        );
        let mut blocked = Box::pin(gate.blocked);
        commonware_macros::select! {
            result = &mut blocked => result.unwrap(),
            result = &mut first_read => panic!("cold body read completed before reaching storage: {result:?}"),
        }
        let mut second_read = Box::pin(
            client.block(second.reference()).instrument(info_span!("test.second_request")),
        );
        commonware_macros::select! {
            result = &mut second_read => panic!("body request bypassed materialization backpressure: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        let headers = expect_within(
            &context,
            std::time::Duration::from_millis(10),
            client.header_segments(vec![(evictor.reference(), 1)], 1024),
            "body backpressure blocked an independent header lookup",
        )
        .await
        .unwrap();
        assert_eq!(headers, vec![vec![evictor.header().clone()]]);

        gate.release.send(()).unwrap();
        assert_eq!(first_read.await.unwrap().as_deref(), Some(first.as_ref()));
        assert_eq!(second_read.await.unwrap().as_deref(), Some(second.as_ref()));
        drop(client);
        assert!(handle.await.is_ok());
    });
    let paths = paths.0.lock();
    for request in ["test.first_request", "test.second_request"] {
        for operation in [
            "multimmit.marshal.materializer.open",
            "multimmit.marshal.materializer.read",
        ] {
            let matching = paths
                .iter()
                .filter(|path| path[0] == operation && path.contains(&request))
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "expected one {operation} under {request}: {paths:?}"
            );
            let unrelated = if request == "test.first_request" {
                "test.second_request"
            } else {
                "test.first_request"
            };
            assert!(
                !matching[0].contains(&unrelated),
                "unrelated request became an ancestor"
            );
        }
    }
}

#[test]
fn cache_hit_body_request_runs_while_body_waiters_are_full() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(47, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CACHE_HIT_WAITERS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let cold = producer_block(&committee, 0, 47);
        let hot = producer_block(&committee, 1, 48);
        let mut initial = config(&context, &committee);
        set_capacity(&mut initial, 1);
        let (client, handle, _delivery) = spawn_catalog(initial, context.child("initial")).await;
        client
            .admit_block(cold.reference(), Arc::clone(&cold))
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut reopened = config(&context, &committee);
        set_capacity(&mut reopened, 1);
        let (client, handle, _delivery) =
            spawn_catalog(reopened, delayed.child("catalog")).await;
        client
            .admit_block(hot.reference(), Arc::clone(&hot))
            .await
            .unwrap();

        // The first cold read holds the only read job; the second waits in the only waiter slot.
        let gate = reads.arm();
        let mut first = Box::pin(client.block(cold.reference()));
        let mut blocked = Box::pin(gate.blocked);
        commonware_macros::select! {
            result = &mut blocked => result.unwrap(),
            result = &mut first => panic!("cold body read completed before reaching storage: {result:?}"),
        }
        let mut second = Box::pin(client.block(cold.reference()));
        commonware_macros::select! {
            result = &mut second => panic!("overlapping body read completed independently: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        let cached = expect_within(
            &context,
            std::time::Duration::from_millis(10),
            client.block(hot.reference()),
            "a cache hit waited for a body waiter slot",
        )
        .await
        .unwrap();
        assert_eq!(cached.as_deref(), Some(hot.as_ref()));

        gate.release.send(()).unwrap();
        assert_eq!(first.await.unwrap().as_deref(), Some(cold.as_ref()));
        assert_eq!(second.await.unwrap().as_deref(), Some(cold.as_ref()));
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn body_read_groups_respect_materialized_cache_budget() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(54, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_MATERIALIZED_GROUP_BOUND")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (64..97)
            .map(|timestamp| producer_block(&committee, 0, timestamp))
            .collect::<Vec<_>>();
        let block_bytes = blocks[0].encode_size();
        assert!(blocks.iter().all(|block| block.encode_size() == block_bytes));

        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, 64);
            config.limits.max_hot_block_bytes = NonZeroUsize::new(block_bytes * 64).unwrap();
            config.limits.max_materialized_block_bytes = NonZeroUsize::new(block_bytes).unwrap();
            config
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), delayed.child("catalog")).await;
        let gate = reads.arm();
        let mut request = Box::pin(client.bodies(
            blocks.iter().map(|block| block.reference()).collect(),
        ));
        let mut blocked = Box::pin(gate.blocked);
        commonware_macros::select! {
            result = &mut blocked => result.unwrap(),
            result = &mut request => panic!("cold body request completed before reaching storage: {result:?}"),
        }
        assert_eq!(
            metric_total(&context.encode(), "materialization_active_bytes"),
            u64::try_from(block_bytes).unwrap(),
        );

        gate.release.send(()).unwrap();
        assert_eq!(request.await.unwrap().len(), blocks.len());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn concurrent_body_reads_share_cold_materialization() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(45, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_COALESCE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let cold = producer_block(&committee, 0, 45);
        let mut initial = config(&context, &committee);
        initial.limits.max_hot_block_bytes = NonZeroUsize::new(cold.encode_size()).unwrap();
        let (client, handle, _delivery) =
            spawn_catalog(initial, context.child("initial")).await;
        client
            .admit_block(cold.reference(), Arc::clone(&cold))
            .await
            .unwrap();
        for timestamp in 46..63 {
            let evictor = producer_block(&committee, 1, timestamp);
            client
                .admit_block(evictor.reference(), evictor)
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut reopened = config(&context, &committee);
        reopened.limits.max_hot_block_bytes = NonZeroUsize::new(cold.encode_size()).unwrap();
        let (client, handle, _delivery) =
            spawn_catalog(reopened, delayed.child("catalog")).await;

        let gate = reads.arm();
        let mut first = Box::pin(client.block(cold.reference()));
        let mut blocked = Box::pin(gate.blocked);
        commonware_macros::select! {
            result = &mut blocked => result.unwrap(),
            result = &mut first => panic!("cold body read completed before reaching storage: {result:?}"),
        }
        let groups_before = metric_total(&context.encode(), "materialization_groups_total");
        let mut second = Box::pin(client.block(cold.reference()));
        let mut progress = Box::pin(client.progress());
        commonware_macros::select! {
            result = &mut progress => { result.unwrap(); },
            result = &mut second => panic!("duplicate body read completed independently: {result:?}"),
        }
        drop(progress);
        let groups_after = metric_total(&context.encode(), "materialization_groups_total");
        assert_eq!(groups_after, groups_before);

        gate.release.send(()).unwrap();
        assert_eq!(first.await.unwrap().as_deref(), Some(cold.as_ref()));
        assert_eq!(second.await.unwrap().as_deref(), Some(cold.as_ref()));
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn sequential_body_reads_reuse_resident_immutable_readers() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(50, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RETAINED_SEGMENT_READER")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        // Two blocks per segment: segments 0..=RESIDENCY exercise the residency bound and
        // the final full segment stays current. Heights start at 128 so every block encodes
        // to the same size and the one-block hot cache always holds only the latest read.
        let blocks = (0..2 * (BODY_READER_RESIDENCY as u32 + 2))
            .map(|offset| producer_block(&committee, offset % 4, 128 + u64::from(offset)))
            .collect::<Vec<_>>();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, 2);
            config.limits.max_hot_block_bytes = NonZeroUsize::new(blocks[0].encode_size()).unwrap();
            config.limits.max_materialized_block_bytes = config.limits.max_hot_block_bytes;
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        // Reopen: the current full segment's reader is offered at spawn, so one resident
        // slot is already occupied.
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("reopened")).await;
        let acquisitions = || metric_total(&context.encode(), "reader_acquisitions_total");
        let read = |index: usize| {
            let client = &client;
            let blocks = &blocks;
            async move {
                assert_eq!(
                    client
                        .block(blocks[index].reference())
                        .await
                        .unwrap()
                        .as_deref(),
                    Some(blocks[index].as_ref())
                );
            }
        };

        read(0).await;
        assert_eq!(
            acquisitions(),
            1,
            "the first cold segment reader was not acquired"
        );
        read(1).await;
        assert_eq!(
            acquisitions(),
            1,
            "sequential reads from one sealed segment reopened its journal"
        );

        // Fill the remaining resident slots with distinct sealed segments.
        let filling = BODY_READER_RESIDENCY - 2;
        for segment in 1..=filling {
            read(2 * segment).await;
        }
        assert_eq!(acquisitions(), 1 + filling as u64);
        read(0).await;
        assert_eq!(
            acquisitions(),
            1 + filling as u64,
            "reader was evicted before the materializer reached residency"
        );

        // The next two distinct segments evict the offered current reader, then the oldest
        // opened reader (segment 0). Revisiting segment 0 must reacquire it.
        read(2 * (filling + 1)).await;
        assert_eq!(
            acquisitions(),
            2 + filling as u64,
            "next segment past residency"
        );
        read(2 * (filling + 2)).await;
        assert_eq!(
            acquisitions(),
            3 + filling as u64,
            "second segment past residency"
        );
        read(0).await;
        assert_eq!(
            acquisitions(),
            4 + filling as u64,
            "reader retention exceeded the materializer's bounded residency"
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn full_admission_reader_avoids_a_cold_acquisition() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(51, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SEALED_READER_HANDOFF")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 51);
        let second = producer_block(&committee, 1, 52);
        let mut config = config(&context, &committee);
        set_capacity(&mut config, 1);
        config.limits.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;

        client
            .admit_block(first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        client
            .admit_block(second.reference(), Arc::clone(&second))
            .await
            .unwrap();
        assert_eq!(
            metric_total(&context.encode(), "reader_acquisitions_total"),
            0
        );
        assert_eq!(
            client.block(first.reference()).await.unwrap().as_deref(),
            Some(first.as_ref())
        );
        assert_eq!(
            metric_total(&context.encode(), "reader_acquisitions_total"),
            0,
            "a full current segment was reopened before its first materialization"
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn recovered_full_reader_survives_segment_rollover() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(52, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RECOVERED_READER_HANDOFF")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 52);
        let second = producer_block(&committee, 1, 53);
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, 1);
            config.limits.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        client
            .admit_block(first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("reopened")).await;
        client
            .admit_block(second.reference(), Arc::clone(&second))
            .await
            .unwrap();
        assert_eq!(
            client.block(first.reference()).await.unwrap().as_deref(),
            Some(first.as_ref())
        );
        assert_eq!(
            metric_total(&context.encode(), "reader_acquisitions_total"),
            0,
            "a recovered full segment was reopened after rollover"
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn body_reads_refresh_current_segment_snapshot() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(49, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_SNAPSHOT_REFRESH")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..6)
            .map(|offset| producer_block(&committee, offset % 4, 49 + u64::from(offset)))
            .collect::<Vec<_>>();
        let mut initial = config(&context, &committee);
        initial.limits.max_hot_block_bytes =
            NonZeroUsize::new(blocks[0].encode_size() * 2).expect("the blocks are non-empty");
        initial.archive.page_cache =
            CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(1));
        let (client, handle, _delivery) =
            spawn_catalog(initial, context.child("initial")).await;
        for block in &blocks[..3] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut reopened = config(&context, &committee);
        reopened.limits.max_hot_block_bytes =
            NonZeroUsize::new(blocks[0].encode_size() * 2).expect("the blocks are non-empty");
        reopened.archive.page_cache =
            CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(1));
        let (client, handle, _delivery) =
            spawn_catalog(reopened, delayed.child("reopened")).await;

        let gate = reads.arm();
        let mut first = Box::pin(client.block(blocks[0].reference()));
        commonware_macros::select! {
            result = &mut first => panic!("body read completed before reaching storage: {result:?}"),
            result = gate.blocked => result.unwrap(),
        }

        for block in &blocks[3..] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        let latest = expect_within(
            &context,
            std::time::Duration::from_millis(100),
            client.block(blocks[3].reference()),
            "newer ready snapshot was not scheduled independently",
        )
        .await
        .unwrap();
        assert_eq!(latest.as_deref(), Some(blocks[3].as_ref()));

        gate.release.send(()).unwrap();
        assert_eq!(first.await.unwrap().as_deref(), Some(blocks[0].as_ref()));
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn cold_segment_acquisition_is_shared_without_blocking_other_segments() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(48, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SEGMENT_READERS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..9)
            .map(|offset| producer_block(&committee, offset % 4, 48 + u64::from(offset)))
            .collect::<Vec<_>>();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, 4);
            config.limits.max_hot_block_bytes =
                NonZeroUsize::new(blocks[0].encode_size() * 4).unwrap();
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let opens = Gates::default();
        let delayed = DelayedOpenContext {
            inner: context.child("delayed"),
            pending: opens.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), delayed.child("catalog")).await;

        let gate = opens.arm();
        let mut first = Box::pin(client.block(blocks[0].reference()));
        commonware_macros::select! {
            result = &mut first => panic!("cold body read completed before reaching storage: {result:?}"),
            result = gate.blocked => result.unwrap(),
        }

        let mut same_segment = Box::pin(client.block(blocks[1].reference()));
        commonware_macros::select! {
            result = &mut same_segment => panic!("same-segment request opened a second reader: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(100)) => {},
        }

        let independent = client.block(blocks[4].reference());
        let independent = expect_within(
            &context,
            std::time::Duration::from_millis(100),
            independent,
            "blocked segment stalled an independent segment",
        )
        .await;
        assert_eq!(independent.unwrap().as_deref(), Some(blocks[4].as_ref()));

        gate.release.send(()).unwrap();
        assert_eq!(first.await.unwrap().as_deref(), Some(blocks[0].as_ref()));
        assert_eq!(
            same_segment.await.unwrap().as_deref(),
            Some(blocks[1].as_ref())
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn producer_admission_progresses_while_cold_body_read_is_blocked() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(42, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_ADMISSION")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let cold = producer_block(&committee, 0, 42);
        let staged = producer_block(&committee, 1, 44);
        let mut initial = config(&context, &committee);
        initial.limits.max_hot_block_bytes =
            NonZeroUsize::new(cold.encode_size()).expect("the block is non-empty");
        let (client, handle, _delivery) =
            spawn_catalog(initial, context.child("catalog")).await;
        client
            .admit_block(cold.reference(), Arc::clone(&cold))
            .await
            .unwrap();
        for timestamp in 43..59 {
            let evictor = producer_block(&committee, 0, timestamp);
            client
                .admit_block(evictor.reference(), evictor)
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut config = config(&context, &committee);
        config.limits.max_hot_block_bytes =
            NonZeroUsize::new(cold.encode_size()).expect("the block is non-empty");
        let (client, handle, _delivery) =
            spawn_catalog(config, delayed.child("catalog")).await;

        let gate = reads.arm();
        let mut blocked = Box::pin(gate.blocked);
        let mut body_read = Box::pin(client.bodies(vec![cold.reference()]));
        commonware_macros::select! {
            result = &mut blocked => result.expect("read gate closed before the body read arrived"),
            result = &mut body_read => panic!("cold body read completed before reaching storage: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(100)) => {
                panic!("cold body read did not reach storage")
            },
        }

        let mut admission =
            Box::pin(client.admit_block(staged.reference(), Arc::clone(&staged)));
        expect_within(
            &context,
            std::time::Duration::from_millis(100),
            &mut admission,
            "durable producer admission was blocked behind a cold body read",
        )
        .await
        .unwrap();
        drop(admission);

        gate.release.send(()).expect("blocked read was dropped");
        assert_eq!(
            body_read.await.unwrap()[0].as_deref(),
            Some(cold.as_ref())
        );
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[rstest::rstest]
#[case::prunable(ArchiveMode::Prunable)]
#[case::immutable(ArchiveMode::Immutable)]
fn committed_output_descriptors_preserve_order_and_bounds(#[case] archive: ArchiveMode) {
    deterministic::Runner::timed(std::time::Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(62, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_OUTPUT_DESCRIPTOR_READS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let count = 3;
        let blocks = (0..count)
            .map(|chain| producer_block(&committee, chain, 62 + u64::from(chain)))
            .collect::<Vec<_>>();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            config.capacities.max_commit_outputs = NonZeroUsize::new(blocks.len()).unwrap();
            config.retention.blocks = archive;
            config
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, &blocks))
            .await
            .unwrap();
        drop(client);
        handle.abort();
        let _ = handle.await;

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("reopened")).await;
        for (max_items, max_bytes, expected) in [
            (NZUsize!(3), NZUsize!(1024 * 1024), 3),
            (NZUsize!(2), NZUsize!(1024 * 1024), 2),
            (NZUsize!(3), NonZeroUsize::MIN, 1),
        ] {
            let outputs = client
                .output_refs(OutputIndex::ZERO, max_items, max_bytes)
                .await
                .unwrap();
            assert_eq!(outputs.len(), expected);
            for (index, (output, block)) in outputs.iter().zip(&blocks).enumerate() {
                assert_eq!(output.index, OutputIndex::new(index as u64));
                assert_eq!(output.reference, block.reference());
                assert_eq!(output.encoded_len, block.encode_size() as u64);
            }
        }
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[test]
fn application_prune_preserves_queued_cold_materialization() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(43, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_PINNED_PRUNE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let candidates = (0..=BODY_READ_CONCURRENCY.get())
            .map(|offset| producer_block(&committee, 0, 100 + offset as u64))
            .collect::<Vec<_>>();
        let current = producer_block(&committee, 1, 200);
        let block_bytes = candidates[0].encode_size();
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, 1);
            config.limits.max_hot_block_bytes =
                NonZeroUsize::new(block_bytes * BODY_READ_CONCURRENCY.get()).unwrap();
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("first")).await;
        for block in candidates.iter().chain(std::iter::once(&current)) {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        let checkpoint = client.checkpoint().await.unwrap();
        let finalized = candidates.last().unwrap();
        let mut emitted = checkpoint.emitted().to_vec();
        emitted[0] = finalized.reference();
        client
            .commit(Commit {
                selected: Vec::new(),
                history: Vec::new(),
                outputs: vec![output_row(OutputIndex::ZERO, finalized)],
                checkpoint: Checkpoint::try_from(CheckpointParts {
                    epoch: checkpoint.epoch(),
                    floor_generation: checkpoint.floor_generation(),
                    archive_layout: checkpoint.archive_layout(),
                    floor: checkpoint.floor(),
                    history: checkpoint.history(),
                    history_index: checkpoint.history_index(),
                    ordered: checkpoint.ordered().to_vec(),
                    emitted,
                    committed: Some(OutputIndex::ZERO),
                })
                .unwrap(),
            })
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), delayed.child("reopened")).await;
        assert_eq!(
            client.delivery_cursor(0, Some(OutputIndex::ZERO)),
            Feedback::Ok
        );
        while client.progress().await.unwrap().acknowledged != Some(OutputIndex::ZERO) {
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        let (releases, blocked): (Vec<_>, Vec<_>) = (0..BODY_READ_CONCURRENCY.get())
            .map(|_| {
                let gate = reads.arm();
                (gate.release, gate.blocked)
            })
            .unzip();
        let expected = candidates
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let mut body_read = Box::pin(client.bodies(expected.clone()));
        let mut blocked = Box::pin(try_join_all(blocked));
        commonware_macros::select! {
            result = &mut blocked => { result.unwrap(); },
            result = &mut body_read => panic!("cold materialization completed before all active reads were gated: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(100)) => {
                panic!("cold materialization did not fill its read window")
            },
        }

        client.prune(0).await.unwrap();
        for release in releases {
            release.send(()).expect("blocked read was dropped");
        }
        let materialized = body_read.await.unwrap();
        assert_eq!(
            materialized
                .iter()
                .map(|block| block.as_ref().unwrap().reference())
                .collect::<Vec<_>>(),
            expected
        );
        client.prune(0).await.unwrap();

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn body_materialization_balances_request_across_read_jobs() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(54, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_READ_CONCURRENCY")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..BODY_READ_CONCURRENCY.get())
            .map(|offset| producer_block(&committee, offset as u32 % 4, 300 + offset as u64))
            .collect::<Vec<_>>();
        let block_bytes = blocks[0].encode_size();
        assert!(blocks.iter().all(|block| block.encode_size() == block_bytes));
        let materialized_bytes = block_bytes * BODY_READ_CONCURRENCY.get() * 3;
        let request_bytes = block_bytes * 2;
        assert!(request_bytes < materialized_bytes / BODY_READ_CONCURRENCY);
        let configure = |context: &DeterministicContext| {
            let mut config = config(context, &committee);
            set_capacity(&mut config, BODY_READ_CONCURRENCY.get());
            config.limits.max_materialized_block_bytes =
                NonZeroUsize::new(materialized_bytes).unwrap();
            config
        };

        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), context.child("initial")).await;
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(configure(&context), delayed.child("reopened")).await;
        // Each read job replays its run through its own storage read, so hold one gate per
        // expected job to observe both in flight.
        let gates = [reads.arm(), reads.arm()];
        let references = blocks
            .iter()
            .take(2)
            .rev()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let mut body_read = Box::pin(client.bodies(references.clone()));
        let [first_gate, second_gate] = gates;
        let mut blocked = Box::pin(futures::future::try_join(
            first_gate.blocked,
            second_gate.blocked,
        ));
        commonware_macros::select! {
            result = &mut blocked => { result.unwrap(); },
            result = &mut body_read => panic!("body materialization completed before reaching storage: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(100)) => {
                panic!("body materialization did not expose the available read jobs")
            },
        }
        assert_eq!(
            metric_total(&context.encode(), "materialization_groups_total"),
            references.len() as u64,
            "one bounded body request did not expose the available read jobs"
        );
        assert_eq!(
            metric_total(&context.encode(), "materialization_active_jobs"),
            references.len() as u64,
        );
        assert_eq!(
            metric_total(&context.encode(), "materialization_active_bytes"),
            u64::try_from(request_bytes).unwrap(),
        );

        for gate in [first_gate.release, second_gate.release] {
            gate.send(()).expect("blocked read was dropped");
        }
        let materialized = body_read.await.unwrap();
        assert_eq!(
            materialized
                .iter()
                .map(|block| block.as_ref().unwrap().reference())
                .collect::<Vec<_>>(),
            references
        );
        drop(client);
        assert!(handle.await.is_ok());
    });
}
