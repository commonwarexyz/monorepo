//! Admission batching, durability cuts, and custody lookups.

use super::*;

#[test]
fn hot_custody_does_not_read_storage() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(39, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HOT_CUSTODY")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), context.child("catalog")).await;
        let block = producer_block(&committee, 0, 39);
        let reference = block.reference();
        client.admit_block(reference, block).await.unwrap();

        let before = metric_total(&context.encode(), "runtime_storage_reads_total");
        let custody = client.wait_for_custody(vec![reference]).await.unwrap();
        let after = metric_total(&context.encode(), "runtime_storage_reads_total");
        assert!(custody[0].is_some());
        assert_eq!(after, before);

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn custody_sync_does_not_block_catalog_reads() {
    deterministic::Runner::default().start(|context| async move {
        let limits = PathLimits::new(2, 2).unwrap();
        let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
        let committee = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ASYNC_CUSTODY")
            .producers(producers)
            .limits(limits)
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let catalog_config = config(&context, &committee);
        let (client, handle, _delivery) = drive_pending_syncs(
            &syncs,
            spawn_catalog(catalog_config, delayed.child("catalog")),
        )
        .await;
        let warm = producer_block(&committee, 0, 9);
        drive_pending_syncs(&syncs, client.admit_block(warm.reference(), warm))
            .await
            .unwrap();
        let block = producer_block(&committee, 0, 10);
        let reference = block.reference();

        syncs.arm();
        let mut admission = Box::pin(client.admit_block(reference, Arc::clone(&block)));
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            commonware_macros::select! {
                result = &mut admission => panic!("custody completed before its sync: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        assert!(
            syncs.calls() > 0,
            "custody did not start a durability operation"
        );

        let mut read = Box::pin(client.block(reference));
        let mut stored = None;
        for _ in 0..100 {
            commonware_macros::select! {
                result = &mut read => {
                    stored = Some(result.expect("catalog read succeeds"));
                    break;
                },
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        let stored = stored.expect("custody sync blocked an independent catalog read");
        drop(read);
        assert_eq!(stored.as_deref(), Some(block.as_ref()));
        commonware_macros::select! {
            result = &mut admission => panic!("custody completed before durability: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        syncs.unblock();
        admission.await.unwrap();
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn custody_waiter_does_not_block_unrelated_commands() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(43, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_WAITER")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let block = producer_block(&committee, 0, 43);
        let reference = block.reference();

        syncs.arm();
        let mut admission = Box::pin(client.admit_block(reference, block));
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            commonware_macros::select! {
                result = &mut admission => panic!("custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        assert!(syncs.calls() > 0, "custody cut did not start");

        let mut custody = Box::pin(client.wait_for_custody(vec![reference]));
        commonware_macros::select! {
            _ = &mut custody => panic!("custody completed before durability"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        let mut progress = Box::pin(client.progress());
        commonware_macros::select! {
            result = &mut progress => { result.unwrap(); },
            _ = context.sleep(std::time::Duration::from_millis(1)) => {
                panic!("custody waiter blocked unrelated catalog work")
            },
        }

        syncs.unblock();
        admission.await.unwrap();
        assert!(custody.await.unwrap()[0].is_some());
        drop(progress);
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn custody_waiters_cover_resolver_and_synchronizer_fanout() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(45, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_FANOUT")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let mut storage_config = config(&context, &committee);
        set_capacity(&mut storage_config, 1);
        storage_config.capacities.resolver_mailbox_size = NZUsize!(1);
        storage_config.capacities.backfill_concurrency = NZUsize!(1);
        let (client, handle, _delivery) =
            spawn_catalog(storage_config, delayed.child("catalog")).await;
        let block = producer_block(&committee, 0, 45);
        let reference = block.reference();

        syncs.arm();
        client
            .stage_blocks(std::slice::from_ref(&block))
            .await
            .unwrap();
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(syncs.calls() > 0, "custody cut did not start");

        let mut first = Box::pin(client.wait_for_custody(vec![reference]));
        commonware_macros::select! {
            _ = &mut first => panic!("first waiter completed before durability"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        client.progress().await.unwrap();
        let mut second = Box::pin(client.wait_for_custody(vec![reference]));
        commonware_macros::select! {
            _ = &mut second => panic!("first synchronizer lookup exceeded the custody bound"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        client.progress().await.unwrap();
        let mut third = Box::pin(client.wait_for_custody(vec![reference]));
        commonware_macros::select! {
            _ = &mut third => panic!("synchronizer lookups exceeded the custody bound"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        client.progress().await.unwrap();

        syncs.unblock();
        assert!(first.await.unwrap()[0].is_some());
        assert!(second.await.unwrap()[0].is_some());
        assert!(third.await.unwrap()[0].is_some());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn custody_is_invisible_until_admission_is_durable() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(35, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_DURABLE_CUSTODY")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let block = producer_block(&committee, 0, 35);
        let reference = block.reference();

        syncs.arm();
        client
            .stage_blocks(std::slice::from_ref(&block))
            .await
            .unwrap();
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(
            syncs.calls() > 0,
            "custody did not start a durability operation"
        );
        assert!(client.block(reference).await.unwrap().is_some());

        let mut custody = Box::pin(client.wait_for_custody(vec![reference]));
        commonware_macros::select! {
            _ = &mut custody => panic!("custody completed before durability"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        syncs.unblock();
        assert!(custody.await.unwrap()[0].is_some());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn admission_cut_triggers_label_reply_and_eager_cuts() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(27, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUT_TRIGGERS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;

        // Hold a reply-bearing staged cut in flight.
        syncs.arm();
        let first = client
            .stage_block(producer_block(&committee, 0, 10))
            .await
            .unwrap();
        client.progress().await.unwrap();
        assert!(syncs.calls() > 0, "staged cut did not start");

        // Reply-free buffered blocks accumulate behind the in-flight cut and start as
        // their own small cut once it completes.
        let buffered = [
            producer_block(&committee, 1, 11),
            producer_block(&committee, 2, 12),
        ];
        client.stage_blocks(&buffered).await.unwrap();

        syncs.unblock();
        first.wait().await.unwrap();
        client.prune(0).await.unwrap();
        let metrics = context.encode();
        assert_eq!(
            metric_total(&metrics, "admission_durability_duration_count"),
            2,
            "the staged cut and the buffered cut both completed"
        );
        assert_eq!(
            metric_total(&metrics, "admission_cut_scheduled_items_total"),
            3,
            "every admission was scheduled"
        );
        assert_eq!(
            metric_sum(
                &metrics,
                "admission_cut_triggers_total",
                &[("trigger", "reply")]
            ),
            1.0,
            "the staged cut is labeled by its waiting reply"
        );
        assert_eq!(
            metric_sum(
                &metrics,
                "admission_cut_triggers_total",
                &[("trigger", "eager")]
            ),
            1.0,
            "the small reply-free cut is labeled as batchable"
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn deferred_barrier_commands_hold_intake_and_admissions_record_dwell() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(26, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INTAKE_INSTRUMENTATION")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let blocks = [
            producer_block(&committee, 0, 10),
            producer_block(&committee, 1, 11),
        ];

        // Block the first admission cut so a second cut queues behind it.
        syncs.arm();
        let first = client.stage_block(blocks[0].clone()).await.unwrap();
        client.progress().await.unwrap();
        assert!(syncs.calls() > 0, "first admission cut did not start");
        let second = client.stage_block(blocks[1].clone()).await.unwrap();

        // A commit-barrier command defers until admission quiescence, and the occupied
        // deferred slot holds back every later command.
        let mut prune = Box::pin(client.prune(0));
        commonware_macros::select! {
            result = &mut prune => panic!("prune completed before quiescence: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        let mut blocked = Box::pin(client.progress());
        commonware_macros::select! {
            result = &mut blocked => panic!("intake proceeded past a deferred barrier: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        syncs.unblock();
        first.wait().await.unwrap();
        second.wait().await.unwrap();
        prune.await.unwrap();
        blocked.await.unwrap();

        let metrics = context.encode();
        assert!(
            metric_total(&metrics, "admission_command_dwell_duration_count") >= 2,
            "both stage commands record admission dwell"
        );
        assert!(
            metric_sum(
                &metrics,
                "work_nanoseconds_total",
                &[("source", "wait"), ("operation", "prune")]
            ) >= 1_000_000.0,
            "the deferred prune wait is separate from command execution"
        );
        assert!(
            metric_sum(
                &metrics,
                "work_calls_total",
                &[("source", "command"), ("operation", "admit")]
            ) >= 2.0,
            "admission handlers are counted independently of background durability"
        );

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn oversized_block_is_rejected_before_custody() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(32, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BLOCK_BOUND")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let mut config = config(&context, &committee);
        config.limits.max_block_bytes = NZUsize!(1);
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
        let block = producer_block(&committee, 0, 32);
        let reference = block.reference();

        assert!(matches!(
            client.stage_blocks(std::slice::from_ref(&block)).await,
            Err(error) if error.is_rejected()
        ));
        assert!(client.block(reference).await.unwrap().is_none());

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn durable_admission_starts_before_deferred_reads() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(24, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_DURABILITY_FAIRNESS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let block = producer_block(&committee, 0, 10);
        let reference = block.reference();
        let (admission_reply, mut admission) = oneshot::channel();
        let (read_reply, read) = oneshot::channel();

        syncs.arm();
        assert!(
            client
                .commands
                .enqueue(traced(Message::Admit {
                    admissions: vec![Admission::Block(reference, block.clone())],
                    reply: AdmissionReply::Durable(admission_reply),
                }))
                .accepted()
        );
        assert!(
            client
                .commands
                .enqueue(traced(Message::Command(Command::Bodies {
                    references: vec![reference],
                    reply: read_reply,
                })))
                .accepted()
        );

        assert_eq!(
            read.await.unwrap().unwrap()[0].as_deref(),
            Some(block.as_ref())
        );
        assert!(
            syncs.calls() > 0,
            "deferred reads overtook the pending durability cut"
        );
        assert!(matches!(
            admission.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        syncs.unblock();
        admission.await.unwrap().unwrap();
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn block_runs_preserve_interleaved_admissions_and_duplicates() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(23, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BLOCK_RUNS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let configure = || {
            let mut config = config(&context, &committee);
            set_capacity(&mut config, 8);
            config
        };
        let blocks = (0..4)
            .map(|chain| producer_block(&committee, chain, 10 + u64::from(chain)))
            .collect::<Vec<_>>();
        let proof = Arc::new(committee.lqc(View::new(1)));
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let history = record.commitment::<Sha256>();
        let (client, handle, _delivery) =
            spawn_catalog(configure(), context.child("initial")).await;
        for timestamp in 100..106 {
            let block = producer_block(&committee, 0, timestamp);
            client.admit_block(block.reference(), block).await.unwrap();
        }
        client
            .request(|reply| Message::Admit {
                admissions: vec![
                    Admission::Block(blocks[0].reference(), blocks[0].clone()),
                    Admission::Block(blocks[0].reference(), blocks[0].clone()),
                    Admission::Block(blocks[1].reference(), blocks[1].clone()),
                    Admission::Lqc(proof.view(), proof.id::<Sha256>(), proof.clone()),
                    Admission::Block(blocks[2].reference(), blocks[2].clone()),
                    Admission::Block(blocks[2].reference(), blocks[2].clone()),
                    Admission::Block(blocks[3].reference(), blocks[3].clone()),
                    Admission::History(proof.view(), history, record.clone()),
                ],
                reply: AdmissionReply::Durable(reply),
            })
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());
        let (client, handle, _delivery) =
            spawn_catalog(configure(), context.child("reopened")).await;
        for block in blocks {
            assert_eq!(
                client.block(block.reference()).await.unwrap().as_deref(),
                Some(block.as_ref())
            );
        }
        assert_eq!(
            client.lqc(proof.id::<Sha256>()).await.unwrap().as_deref(),
            Some(proof.as_ref())
        );
        assert_eq!(
            client.history(history).await.unwrap().as_deref(),
            Some(record.as_ref())
        );
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn staged_admissions_coalesce_one_trailing_cut_and_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(23, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_PIPELINE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let mut storage_config = config(&context, &committee);
        storage_config.archive.items_per_section = NZU64!(1024);
        let (client, handle, _delivery) =
            spawn_catalog(storage_config, delayed.child("catalog")).await;
        let blocks = [
            producer_block(&committee, 0, 10),
            producer_block(&committee, 1, 11),
            producer_block(&committee, 2, 12),
        ];

        syncs.arm();
        let first = client.stage_block(blocks[0].clone()).await.unwrap();
        client.progress().await.unwrap();
        let first_cut_syncs = syncs.calls();
        assert!(first_cut_syncs > 0, "first custody cut did not start");
        let mut first = Box::pin(first.wait());
        commonware_macros::select! {
            result = &mut first => panic!("first custody completed before durability: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        let second = client.stage_block(blocks[1].clone()).await.unwrap();
        let mut second = Box::pin(second.wait());
        commonware_macros::select! {
            result = &mut second => panic!("second custody completed before durability: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        assert_eq!(
            client.block(blocks[1].reference()).await.unwrap().as_deref(),
            Some(blocks[1].as_ref())
        );

        let third = client.stage_block(blocks[2].clone()).await.unwrap();
        drop(third);
        assert_eq!(
            client.block(blocks[2].reference()).await.unwrap().as_deref(),
            Some(blocks[2].as_ref())
        );
        assert_eq!(
            syncs.calls(),
            first_cut_syncs,
            "trailing admissions started separate sync cuts"
        );

        release_next_pending_syncs(&syncs, first_cut_syncs);
        first.await.unwrap();
        for _ in 0..100 {
            if syncs.calls() > first_cut_syncs {
                break;
            }
            commonware_macros::select! {
                result = &mut second => panic!("second custody escaped the first cut: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        let trailing_cut_syncs = syncs.calls() - first_cut_syncs;
        assert!(trailing_cut_syncs > 0, "trailing custody cut did not start");
        commonware_macros::select! {
            result = &mut second => panic!("second custody completed before its cut: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        release_next_pending_syncs(&syncs, trailing_cut_syncs);
        second.await.unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let mut storage_config = config(&context, &committee);
        storage_config.archive.items_per_section = NZU64!(1024);
        let (client, handle, _delivery) =
            spawn_catalog(storage_config, context.child("reopen")).await;
        for block in blocks {
            assert_eq!(
                client.block(block.reference()).await.unwrap().as_deref(),
                Some(block.as_ref())
            );
        }
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn bounded_admission_batch_moves_to_the_next_trailing_cut() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(44, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ADMISSION_BOUNDARY")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let mut storage_config = config(&context, &committee);
        set_capacity(&mut storage_config, 2);
        storage_config.archive.items_per_section = NZU64!(1024);
        let (client, handle, _delivery) =
            spawn_catalog(storage_config, delayed.child("catalog")).await;
        let blocks = [
            producer_block(&committee, 0, 40),
            producer_block(&committee, 1, 41),
            producer_block(&committee, 2, 42),
            producer_block(&committee, 3, 43),
        ];

        syncs.arm();
        let mut first = Box::pin(client.admit_block(blocks[0].reference(), blocks[0].clone()));
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            commonware_macros::select! {
                result = &mut first => panic!("first custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        client.progress().await.unwrap();
        let first_cut_syncs = syncs.calls();
        assert!(first_cut_syncs > 0, "first custody cut did not start");

        let mut trailing = Box::pin(client.admit_block(
            blocks[1].reference(),
            blocks[1].clone(),
        ));
        commonware_macros::select! {
            result = &mut trailing => panic!("trailing custody completed before durability: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        let mut batch = Box::pin(client.stage_blocks(&blocks[2..]));
        commonware_macros::select! {
            result = &mut batch => panic!("batch crossed a full trailing-cut boundary: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        release_next_pending_syncs(&syncs, first_cut_syncs);
        first.await.unwrap();
        let mut admitted = false;
        for _ in 0..100 {
            commonware_macros::select! {
                result = &mut batch => {
                    result.unwrap();
                    admitted = true;
                    break;
                },
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        assert!(admitted, "bounded batch did not enter the next trailing cut");
        drop(batch);

        syncs.unblock();
        trailing.await.unwrap();
        let custody = client
            .wait_for_custody(vec![blocks[2].reference(), blocks[3].reference()])
            .await
            .unwrap();
        assert!(custody.into_iter().all(|value| value.is_some()));
        assert!(client.block(blocks[2].reference()).await.unwrap().is_some());
        assert!(client.block(blocks[3].reference()).await.unwrap().is_some());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn staged_lqc_buffers_without_durability() {
    deterministic::Runner::default().start(|context| async move {
        let limits = PathLimits::new(2, 2).unwrap();
        let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
        let committee = Committee::<MinPk>::builder(9, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_STAGED_LQC")
            .producers(producers)
            .limits(limits)
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let proof = Arc::new(committee.lqc(View::new(1)));
        let id = proof.id::<Sha256>();

        syncs.arm();
        client
            .stage_lqc(proof.view(), id, Arc::clone(&proof))
            .await
            .unwrap();
        assert_eq!(syncs.calls(), 0);
        assert_eq!(
            client.lqc(id).await.unwrap().as_deref(),
            Some(proof.as_ref())
        );

        syncs.unblock();
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn concurrent_admissions_share_one_cut_and_reject_mismatched_identities() {
    deterministic::Runner::default().start(|context| async move {
        let lifecycle = Lifecycle::new();
        let (client, handle, _delivery) = open(&context, "admissions", &lifecycle.committee).await;
        lifecycle.admit_all(&client).await;
        assert_eq!(
            metric_total(&context.encode(), "admission_cut_scheduled_items_total"),
            6,
        );

        let proof = &lifecycle.proof;
        let alternate = &lifecycle.alternate;
        let reference = lifecycle.block.reference();
        assert_eq!(
            client.lqc(proof.id::<Sha256>()).await.unwrap().as_deref(),
            Some(proof.as_ref())
        );
        assert_eq!(
            client
                .lqc(alternate.id::<Sha256>())
                .await
                .unwrap()
                .as_deref(),
            Some(alternate.as_ref())
        );
        assert_eq!(
            client.latest_lqc().await.unwrap().unwrap().view(),
            View::new(3)
        );
        assert_eq!(
            client
                .block_by_digest(reference.chain(), reference.digest())
                .await
                .unwrap()
                .as_deref(),
            Some(lifecycle.block.as_ref())
        );

        let bad_id = CertificateId::new(Sha256::hash(&[b"wrong LQC identity"]));
        assert!(matches!(
            client.admit_lqc(proof.view(), bad_id, proof.clone()).await,
            Err(error) if error.is_rejected()
        ));
        let wrong_parent = Arc::new(
            TipRecord::at_tips(
                Sha256::hash(&[b"wrong history parent"]),
                lifecycle.committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        assert!(matches!(
            client
                .admit_finality(proof.view(), proof.id::<Sha256>(), proof.clone(), wrong_parent)
                .await,
            Err(error) if error.is_rejected()
        ));
        let bad_reference = BlockRef::new(
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"wrong block identity"]),
        );
        assert!(matches!(
            client
                .admit_block(bad_reference, lifecycle.block.clone())
                .await,
            Err(error) if error.is_rejected()
        ));
        drop(client);
        assert!(handle.await.is_ok());
    });
}
