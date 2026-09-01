//! The commit pipeline, delivery handoff, and delivery-cursor mirroring.

use super::*;

#[test]
fn warmed_commit_retains_every_requested_hot_body() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(41, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_HANDOFF")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 41);
        let filler = producer_block(&committee, 0, 42);
        let second = producer_block(&committee, 1, 43);
        let mut first_config = config(&context, &committee);
        first_config.limits.max_hot_block_bytes =
            NonZeroUsize::new(first.encode_size() * 2).unwrap();
        first_config.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, _delivery) = spawn_catalog(first_config, context.child("first")).await;
        for block in [&first, &filler, &second] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        drop(client);
        assert!(handle.await.is_ok());

        let mut reopened_config = config(&context, &committee);
        reopened_config.limits.max_hot_block_bytes =
            NonZeroUsize::new(first.encode_size() * 2).unwrap();
        reopened_config.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, mut delivery) =
            spawn_catalog(reopened_config, context.child("reopened")).await;
        for references in [
            vec![first.reference(), filler.reference()],
            vec![first.reference(), second.reference()],
        ] {
            assert!(
                client
                    .bodies(references)
                    .await
                    .unwrap()
                    .into_iter()
                    .all(|block| block.is_some())
            );
        }

        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, [&first, &second]))
            .await
            .unwrap();
        assert_eq!(next_batch(&mut delivery).await.outputs.len(), 2);

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn live_handoff_takes_priority_over_materialized_history() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(47, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SPARSE_HANDOFF")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 47);
        let second = producer_block(&committee, 1, 48);
        let mut initial = config(&context, &committee);
        initial.limits.max_hot_block_bytes = NonZeroUsize::new(second.encode_size()).unwrap();
        initial.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, _delivery) = spawn_catalog(initial, context.child("first")).await;
        client
            .admit_block(first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let mut reopened = config(&context, &committee);
        reopened.limits.max_hot_block_bytes = NonZeroUsize::new(second.encode_size()).unwrap();
        reopened.limits.max_materialized_block_bytes =
            NonZeroUsize::new(first.encode_size()).unwrap();
        reopened.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, mut delivery) =
            spawn_catalog(reopened, context.child("reopened")).await;
        assert!(client.bodies(vec![first.reference()]).await.unwrap()[0].is_some());
        client
            .admit_block(second.reference(), Arc::clone(&second))
            .await
            .unwrap();

        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, [&first, &second]))
            .await
            .unwrap();

        let batch = next_batch(&mut delivery).await;
        assert_eq!(batch.outputs.len(), 1);
        let DeliveryOutput::Hot(output) = &batch.outputs[0] else {
            panic!("the retained output carries its body");
        };
        assert_eq!(output.stored.index, OutputIndex::new(1));
        assert_eq!(output.block.as_ref(), second.as_ref());

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn recovered_handoff_survives_live_cache_eviction() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(49, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RECOVERED_HANDOFF")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let recovered = producer_block(&committee, 0, 49);
        let filler = producer_block(&committee, 1, 50);
        let mut catalog_config = config(&context, &committee);
        catalog_config.limits.max_hot_block_bytes =
            NonZeroUsize::new(recovered.encode_size()).unwrap();
        let (client, handle, mut delivery) =
            spawn_catalog(catalog_config, context.child("catalog")).await;
        for block in [&recovered, &filler] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }

        let current = client.checkpoint().await.unwrap();
        let mut emitted = current.emitted().to_vec();
        emitted[0] = recovered.reference();
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted,
            committed: Some(OutputIndex::ZERO),
        })
        .unwrap();
        client
            .start_commit(
                Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &recovered)],
                    checkpoint,
                },
                vec![hot_output(
                    OutputIndex::ZERO,
                    &recovered,
                    current.floor_generation(),
                )],
            )
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();

        let batch = next_batch(&mut delivery).await;
        assert_eq!(batch.outputs.len(), 1);
        let DeliveryOutput::Hot(output) = &batch.outputs[0] else {
            panic!("the handed-off output carries its body");
        };
        assert_eq!(output.stored.index, OutputIndex::ZERO);
        assert_eq!(output.block.as_ref(), recovered.as_ref());

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn commits_buffer_a_second_cut_before_the_first_is_durable() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(18, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COMMIT_PIPELINE")
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
        let current = client.checkpoint().await.unwrap();
        let first = producer_block(&committee, 0, 20);
        let second = producer_block(&committee, 1, 21);
        drive_pending_syncs(
            &syncs,
            client.admit_block(first.reference(), Arc::clone(&first)),
        )
        .await
        .unwrap();
        drive_pending_syncs(
            &syncs,
            client.admit_block(second.reference(), Arc::clone(&second)),
        )
        .await
        .unwrap();

        let first_commit = output_commit(&current, [&first]);
        let second_commit = output_commit(&first_commit.checkpoint, [&second]);

        let completed_before_pipeline = syncs.completions();
        syncs.arm();
        let first_token = client
            .start_commit(first_commit, Vec::new())
            .await
            .unwrap();
        let second_token = client
            .start_commit(second_commit, Vec::new())
            .await
            .unwrap();

        let first_archive_syncs = syncs.calls();
        assert!(first_archive_syncs > 0, "first archive cut did not start");
        assert_eq!(client.progress().await.unwrap().committed, None);
        assert!(matches!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await,
            Err(error) if error.is_rejected()
        ));

        let mut first_wait = Box::pin(first_token.wait());
        release_next_pending_syncs(&syncs, first_archive_syncs);
        for _ in 0..100 {
            if syncs.calls() >= first_archive_syncs + 2 {
                break;
            }
            commonware_macros::select! {
                result = &mut first_wait => panic!("first cut published before its checkpoint sync: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        let overlap_syncs = syncs.calls() - first_archive_syncs;
        assert!(
            overlap_syncs >= 2,
            "checkpoint publication did not overlap the next archive cut"
        );
        assert_eq!(client.progress().await.unwrap().committed, None);

        let second_archives = {
            let mut pending = syncs.lock();
            assert_eq!(pending.len(), overlap_syncs);
            pending.drain(1..).collect::<Vec<_>>()
        };
        // Recovery markers can remain unpolled until the next archive request. Only
        // syncs already waiting here participate in this cut's data durability.
        let mut second_archive_syncs = 0;
        for sync in second_archives {
            second_archive_syncs += usize::from(sync.blocked.now_or_never().is_some());
            let _ = sync.release.send(Ok(()));
        }
        assert!(second_archive_syncs > 0);
        let completed_through_second_archives = completed_before_pipeline
            + first_archive_syncs
            + second_archive_syncs;
        for _ in 0..100 {
            if syncs.completions() >= completed_through_second_archives {
                break;
            }
            commonware_macros::select! {
                result = &mut first_wait => panic!("second archives bypassed the first checkpoint: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
        }
        assert_eq!(
            syncs.completions(),
            completed_through_second_archives,
            "second archive cut did not finish ahead of the first checkpoint"
        );

        let mut second_wait = Box::pin(second_token.wait());
        release_next_pending_syncs(&syncs, 1);
        first_wait.await.unwrap();
        assert_eq!(
            client.progress().await.unwrap().committed,
            Some(OutputIndex::ZERO)
        );
        assert_eq!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await
                .unwrap()[0]
                .reference,
            first.reference()
        );
        assert!(matches!(
            client
                .output_refs(OutputIndex::new(1), NZUsize!(1), NZUsize!(1024 * 1024))
                .await,
            Err(error) if error.is_rejected()
        ));
        commonware_macros::select! {
            result = &mut second_wait => panic!("second cut published with the first checkpoint: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }

        release_next_pending_syncs(&syncs, 1);
        second_wait.await.unwrap();
        assert_eq!(
            client.progress().await.unwrap().committed,
            Some(OutputIndex::new(1))
        );
        assert_eq!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1024 * 1024))
                .await
                .unwrap()
                .len(),
            2
        );
        let singleton = client
            .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1))
            .await
            .unwrap();
        assert_eq!(singleton.len(), 1);
        assert_eq!(singleton[0].reference, first.reference());
        let batch = client
            .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1024 * 1024))
            .await
            .unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[1].reference, second.reference());

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn ready_checkpoint_completion_precedes_buffered_progress() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(46, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COMPLETION_FAIRNESS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let opens = Gates::default();
        let delayed = DelayedOpenContext {
            inner: DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            },
            pending: opens.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        let first = producer_block(&committee, 0, 46);
        let second = producer_block(&committee, 1, 47);
        for block in [&first, &second] {
            drive_pending_syncs(
                &syncs,
                client.admit_block(block.reference(), Arc::clone(block)),
            )
            .await
            .unwrap();
        }
        let current = client.checkpoint().await.unwrap();
        let first_commit = output_commit(&current, [&first]);
        let second_commit = output_commit(&first_commit.checkpoint, [&second]);

        syncs.arm();
        let token = client.start_commit(first_commit, Vec::new()).await.unwrap();
        let archive_syncs = syncs.calls();
        release_next_pending_syncs(&syncs, archive_syncs);
        for _ in 0..100 {
            if syncs.calls() > archive_syncs {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(syncs.calls(), archive_syncs + 1);

        // Hold the catalog inside the second commit while its finalized row opens a section.
        let Gated {
            release,
            mut blocked,
        } = opens.arm();
        let mut second_token = Box::pin(client.start_commit(second_commit, Vec::new()));
        select! {
            result = &mut blocked => result.unwrap(),
            _ = &mut second_token => panic!("second commit accepted before its section opened"),
        }

        let mut progress = Vec::new();
        for _ in 0..8 {
            let (reply, receiver) = oneshot::channel();
            let _ = client
                .commands
                .enqueue(traced(Message::Command(Command::Progress { reply })));
            progress.push(receiver);
        }
        release_next_pending_syncs(&syncs, 1);
        release.send(()).unwrap();
        let second_token = second_token.await.unwrap();
        for receiver in progress {
            assert_eq!(
                receiver.await.unwrap().unwrap().committed,
                Some(OutputIndex::ZERO)
            );
        }
        token.wait().await.unwrap();
        drive_pending_syncs(&syncs, second_token.wait())
            .await
            .unwrap();

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn acknowledgement_durability_is_independent_of_commit_publication() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(62, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INDEPENDENT_ACK")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let config = config(&context, &committee);
        let (delivery_client, delivery_commands) =
            delivery::channel(delayed.child("delivery_mailbox"));
        let (client, catalog_handle, reporter, delivery_handle) =
            spawn_catalog_delivery(config, &delayed, delivery_client, delivery_commands).await;

        let current = client.checkpoint().await.unwrap();
        let first = producer_block(&committee, 0, 62);
        client
            .stage_blocks(std::slice::from_ref(&first))
            .await
            .unwrap();
        let mut first_emitted = current.emitted().to_vec();
        first_emitted[0] = first.reference();
        let first_checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted: first_emitted.clone(),
            committed: Some(OutputIndex::ZERO),
        })
        .unwrap();
        drive_pending_syncs(
            &syncs,
            client.commit(Commit {
                selected: Vec::new(),
                history: Vec::new(),
                outputs: vec![output_row(OutputIndex::ZERO, &first)],
                checkpoint: first_checkpoint,
            }),
        )
        .await
        .unwrap();
        for _ in 0..100 {
            if reporter
                .pending
                .lock()
                .iter()
                .any(|(index, _)| *index == OutputIndex::ZERO)
            {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }

        let second = producer_block(&committee, 1, 63);
        drive_pending_syncs(
            &syncs,
            client.admit_block(second.reference(), Arc::clone(&second)),
        )
        .await
        .unwrap();
        let current = client.checkpoint().await.unwrap();
        let mut second_emitted = first_emitted;
        second_emitted[1] = second.reference();
        let second_checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted: second_emitted,
            committed: Some(OutputIndex::new(1)),
        })
        .unwrap();

        syncs.arm();
        let commit = client
            .start_commit(
                Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::new(1), &second)],
                    checkpoint: second_checkpoint,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        let mut commit_syncs = 0;
        for _ in 0..100 {
            context.sleep(std::time::Duration::from_millis(1)).await;
            let calls = syncs.calls();
            if calls == commit_syncs && calls > 0 {
                break;
            }
            commit_syncs = calls;
        }
        assert!(commit_syncs > 0, "commit durability did not start");
        assert!(reporter.acknowledge(OutputIndex::ZERO));
        for _ in 0..100 {
            if syncs.calls() > commit_syncs {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(syncs.calls(), commit_syncs + 1);

        let acknowledgement_sync = syncs.lock().pop().unwrap();
        let _ = acknowledgement_sync.release.send(Ok(()));
        for _ in 0..100 {
            if client.progress().await.unwrap().acknowledged == Some(OutputIndex::ZERO) {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(
            client.progress().await.unwrap().acknowledged,
            Some(OutputIndex::ZERO)
        );

        let mut publication = Box::pin(commit.wait());
        commonware_macros::select! {
            result = &mut publication => {
                panic!("commit completed before its durability was released: {result:?}")
            },
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        drive_pending_syncs(&syncs, publication).await.unwrap();
        delivery_handle.abort();
        let _ = delivery_handle.await;
        drop(client);
        assert!(catalog_handle.await.is_ok());
    });
}

#[test]
fn application_ready_acknowledgements_refill_while_cursor_sync_is_active() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(63, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ACK_COALESCING")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let mut config = config(&context, &committee);
        config.capacities.max_commit_outputs = NZUsize!(4);
        config.capacities.max_pending_acks = NZUsize!(1);
        let (delivery_client, delivery_commands) =
            delivery::channel(delayed.child("delivery_mailbox"));
        let (client, catalog_handle, reporter, delivery_handle) =
            spawn_catalog_delivery(config, &delayed, delivery_client, delivery_commands).await;

        let blocks = (0..4)
            .map(|chain| producer_block(&committee, chain, 63 + u64::from(chain)))
            .collect::<Vec<_>>();
        client.stage_blocks(&blocks).await.unwrap();
        let current = client.checkpoint().await.unwrap();
        let mut emitted = current.emitted().to_vec();
        for block in &blocks {
            emitted[block.reference().chain().get() as usize] = block.reference();
        }
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted,
            committed: Some(OutputIndex::new(3)),
        })
        .unwrap();
        drive_pending_syncs(
            &syncs,
            client.commit(Commit {
                selected: Vec::new(),
                history: Vec::new(),
                outputs: blocks
                    .iter()
                    .enumerate()
                    .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                    .collect(),
                checkpoint,
            }),
        )
        .await
        .unwrap();

        wait_for_report(&context, &reporter, OutputIndex::ZERO).await;
        syncs.arm();
        let syncs_before = syncs.calls();
        assert!(reporter.acknowledge(OutputIndex::ZERO));
        for _ in 0..100 {
            if syncs.calls() > syncs_before {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(syncs.calls(), syncs_before + 1);

        for index in 1..4 {
            let index = OutputIndex::new(index);
            wait_for_report(&context, &reporter, index).await;
            assert!(reporter.acknowledge(index));
        }
        for _ in 0..100 {
            if metric_total(&context.encode(), "delivery_pending_durability") == 4 {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(syncs.calls(), syncs_before + 1);
        assert_eq!(client.progress().await.unwrap().acknowledged, None);
        let metrics = context.encode();
        assert_eq!(metric_total(&metrics, "delivery_pending_durability"), 4);
        assert_eq!(metric_total(&metrics, "delivery_in_flight"), 0);

        let acknowledgement_sync = syncs.lock().pop().unwrap();
        acknowledgement_sync.release.send(Ok(())).unwrap();
        for _ in 0..100 {
            if syncs.calls() == syncs_before + 2 {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(syncs.calls(), syncs_before + 2);
        let acknowledgement_sync = syncs.lock().pop().unwrap();
        acknowledgement_sync.release.send(Ok(())).unwrap();
        for _ in 0..100 {
            if client.progress().await.unwrap().acknowledged == Some(OutputIndex::new(3)) {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(
            client.progress().await.unwrap().acknowledged,
            Some(OutputIndex::new(3))
        );
        let metrics = context.encode();
        assert_eq!(metric_total(&metrics, "delivery_pending_durability"), 0);
        assert_eq!(
            metric_total(&metrics, "delivery_acknowledgement_starts_total_total",),
            2
        );
        assert_eq!(
            metric_total(&metrics, "delivery_acknowledgements_total_total",),
            4
        );

        delivery_handle.abort();
        let _ = delivery_handle.await;
        drop(client);
        assert!(catalog_handle.await.is_ok());
    });
}

#[test]
fn commit_block_byte_bound_rejects_multi_block_overshoot_but_allows_a_single_block() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(30, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COMMIT_BYTES")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let mut config = config(&context, &committee);
        config.capacities.max_commit_outputs = NZUsize!(2);
        config.limits.max_commit_block_bytes = NZUsize!(1);
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
        let current = client.checkpoint().await.unwrap();
        let first = producer_block(&committee, 0, 30);
        let second = producer_block(&committee, 1, 31);
        client
            .stage_blocks(std::slice::from_ref(&first))
            .await
            .unwrap();
        client
            .stage_blocks(std::slice::from_ref(&second))
            .await
            .unwrap();

        let mut emitted = current.emitted().to_vec();
        emitted[0] = first.reference();
        emitted[1] = second.reference();
        let oversized = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted,
            committed: Some(OutputIndex::new(1)),
        })
        .unwrap();
        let result = client
            .start_commit(
                Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![
                        output_row(OutputIndex::ZERO, &first),
                        output_row(OutputIndex::new(1), &second),
                    ],
                    checkpoint: oversized,
                },
                Vec::new(),
            )
            .await;
        assert!(matches!(result, Err(error) if error.is_rejected()));

        let mut emitted = current.emitted().to_vec();
        emitted[0] = first.reference();
        let singleton = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: current.floor(),
            history: current.history(),
            history_index: current.history_index(),
            ordered: current.ordered().to_vec(),
            emitted,
            committed: Some(OutputIndex::ZERO),
        })
        .unwrap();
        client
            .start_commit(
                Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &first)],
                    checkpoint: singleton,
                },
                Vec::new(),
            )
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();

        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn commit_rejects_an_oversized_batch_before_publication() {
    deterministic::Runner::default().start(|context| async move {
        let lifecycle = Lifecycle::new();
        let (client, handle, _delivery) = open(&context, "oversized", &lifecycle.committee).await;
        lifecycle.admit_all(&client).await;

        let mut emitted = lifecycle.emitted();
        emitted[1] = lifecycle.other_chain.reference();
        let oversized = Commit {
            selected: Vec::new(),
            history: vec![HistoryOpening {
                commitment: lifecycle.history,
                record: lifecycle.record.clone(),
            }],
            outputs: vec![
                output_row(OutputIndex::ZERO, &lifecycle.block),
                output_row(OutputIndex::new(1), &lifecycle.other_chain),
            ],
            checkpoint: checkpoint(
                &lifecycle.committee,
                0,
                lifecycle.committee.config.genesis().lqc(),
                lifecycle.history,
                0,
                emitted,
                Some(OutputIndex::new(1)),
            ),
        };
        assert!(matches!(
            client.commit(oversized).await,
            Err(error) if error.is_rejected()
        ));
        assert_eq!(client.progress().await.unwrap().committed, None);
        assert!(matches!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await,
            Err(error) if error.is_rejected()
        ));
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn delivery_cursor_mirror_rejects_contradictions_and_survives_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let lifecycle = Lifecycle::new();
        let child = context.child("cursor");
        let (delivery_client, _delivery) = delivery::channel(child.child("delivery_mailbox"));
        let config = config(&context, &lifecycle.committee);
        let Opened {
            catalog: client,
            catalog_handle: handle,
            promoter: _,
            mut delivery_store,
        } = open_storage::<_, _, Sha256, _, _>(
            child,
            &config,
            &config.actor_bounds().unwrap(),
            delivery_client,
        )
        .await
        .unwrap();
        lifecycle.admit_all(&client).await;
        client.commit(lifecycle.intermediate()).await.unwrap();
        client.commit(lifecycle.finalizing()).await.unwrap();

        assert!(matches!(
            client
                .reset_delivery_cursor(0, Some(OutputIndex::new(1)))
                .await,
            Err(error) if error.is_rejected()
        ));
        delivery_store
            .start_acknowledgement(0, OutputIndex::ZERO)
            .await
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            client.delivery_cursor(0, Some(OutputIndex::ZERO)),
            Feedback::Ok
        );
        while client.progress().await.unwrap().acknowledged != Some(OutputIndex::ZERO) {
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(matches!(
            delivery_store
                .start_acknowledgement(0, OutputIndex::ZERO)
                .await,
            Err(StorageError::Invalid(_))
        ));
        drop(delivery_store);
        drop(client);
        assert!(handle.await.is_ok());

        let (client, handle, _delivery) =
            open(&context, "cursor_reopen", &lifecycle.committee).await;
        assert_eq!(
            client.progress().await.unwrap(),
            MarshalProgress {
                floor_generation: 0,
                floor: lifecycle.proof.id::<Sha256>(),
                committed: Some(OutputIndex::ZERO),
                acknowledged: Some(OutputIndex::ZERO),
            }
        );
        let reopened = client
            .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
            .await
            .unwrap()[0]
            .reference;
        assert_eq!(reopened, lifecycle.block.reference());
        assert_eq!(
            client.block(reopened).await.unwrap().as_deref(),
            Some(lifecycle.block.as_ref())
        );
        drop(client);
        assert!(handle.await.is_ok());
    });
}
