//! Reopening after crashes at commit and cleanup boundaries.

use super::*;

#[test]
fn distinct_same_view_lqcs_reopen_and_prune_by_ordinal() {
    deterministic::Runner::default().start(|context| async move {
        let limits = PathLimits::new(2, 2).unwrap();
        let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
        let committee = Committee::<MinPk>::builder(9, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SAME_VIEW")
            .producers(producers)
            .limits(limits)
            .build();
        let first = lqc(&committee, 1, 0..5);
        let second = lqc(&committee, 1, 1..6);
        let first_id = first.id::<Sha256>();
        let second_id = second.id::<Sha256>();
        assert_ne!(first_id, second_id);
        assert_eq!(first.view(), second.view());
        assert_eq!(first.leader().history(), second.leader().history());

        let mut first_config = config(&context, &committee);
        first_config.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, _delivery) =
            spawn_catalog(first_config, context.child("first_open")).await;
        let current = client.checkpoint().await.unwrap();
        let record = Arc::new(
            TipRecord::at_tips(
                current.history(),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let history = record.commitment::<Sha256>();
        assert_eq!(first.leader().history(), history);
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: second_id,
            history,
            history_index: Some(0),
            ordered: current.ordered().to_vec(),
            emitted: current.emitted().to_vec(),
            committed: current.committed(),
        })
        .unwrap();
        client
            .commit(Commit {
                selected: vec![
                    SelectedLqc {
                        view: first.view(),
                        id: first_id,
                        proof: first.clone(),
                    },
                    SelectedLqc {
                        view: second.view(),
                        id: second_id,
                        proof: second.clone(),
                    },
                ],
                history: vec![HistoryOpening {
                    commitment: history,
                    record,
                }],
                outputs: Vec::new(),
                checkpoint,
            })
            .await
            .unwrap();
        drop(client);
        assert!(handle.await.is_ok());

        let mut reopen_config = config(&context, &committee);
        reopen_config.capacities.max_commit_outputs = NZUsize!(2);
        let (client, handle, _delivery) =
            spawn_catalog(reopen_config, context.child("reopen")).await;
        assert!(client.final_lqc(first_id).await.unwrap());
        assert!(client.final_lqc(second_id).await.unwrap());
        client.prune(0).await.unwrap();
        assert!(!client.final_lqc(first_id).await.unwrap());
        assert!(client.final_lqc(second_id).await.unwrap());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[rstest::rstest]
#[case::outputs(false)]
#[case::all_archives(true)]
fn archive_durable_checkpoint_volatile_commit_replays_exactly(#[case] all_archives: bool) {
    let paths = SpanPaths::default();
    let subscriber = tracing_subscriber::registry().with(paths.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(44, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CHECKPOINT_CRASH")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let block = producer_block(&committee, 0, 44);
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let (client, handle, _delivery) =
            spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
        drive_pending_syncs(
            &syncs,
            client.admit_block(block.reference(), Arc::clone(&block)),
        )
        .await
        .unwrap();
        let current = client.checkpoint().await.unwrap();
        let proof = lqc(&committee, 1, 0..5);
        let record =
            Arc::new(TipRecord::at_tips(current.history(), current.ordered().to_vec()).unwrap());
        let history = record.commitment::<Sha256>();
        assert_eq!(proof.leader().history(), history);
        let mut emitted = current.emitted().to_vec();
        emitted[0] = block.reference();
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation(),
            archive_layout: current.archive_layout(),
            floor: if all_archives {
                proof.id::<Sha256>()
            } else {
                current.floor()
            },
            history: if all_archives {
                history
            } else {
                current.history()
            },
            history_index: if all_archives {
                Some(0)
            } else {
                current.history_index()
            },
            ordered: current.ordered().to_vec(),
            emitted,
            committed: Some(OutputIndex::ZERO),
        })
        .unwrap();

        let batch = || Commit {
            selected: if all_archives {
                vec![SelectedLqc {
                    view: proof.view(),
                    id: proof.id::<Sha256>(),
                    proof: proof.clone(),
                }]
            } else {
                Vec::new()
            },
            history: if all_archives {
                vec![HistoryOpening {
                    commitment: history,
                    record: record.clone(),
                }]
            } else {
                Vec::new()
            },
            outputs: vec![output_row(OutputIndex::ZERO, &block)],
            checkpoint: checkpoint.clone(),
        };
        syncs.arm();
        let token = client.start_commit(batch(), Vec::new()).await.unwrap();
        let archive_syncs = syncs.calls();
        assert!(archive_syncs > 0, "finalized archive cut did not start");
        let mut publication = Box::pin(token.wait());
        wait_for_checkpoint_sync(&context, &syncs, &paths, &mut publication).await;
        drop(publication);
        handle.abort();
        drop(client);
        let _ = handle.await;

        let (client, handle, _delivery) =
            open(&context, "reopened_checkpoint_crash", &committee).await;
        assert_eq!(client.progress().await.unwrap().committed, None);
        assert!(matches!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await,
            Err(error) if error.is_rejected()
        ));
        client.commit(batch()).await.unwrap();
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
            block.reference()
        );
        if all_archives {
            assert!(client.final_lqc(proof.id::<Sha256>()).await.unwrap());
            assert_eq!(
                client.history(history).await.unwrap().as_deref(),
                Some(record.as_ref())
            );
        }
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn archive_ahead_lqc_ordinal_is_skipped_after_reopen() {
    let paths = SpanPaths::default();
    let subscriber = tracing_subscriber::registry().with(paths.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(68, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_LQC_ORDINAL_CRASH")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();

        for (mode, label, delayed_label, reopen_label) in [
            (
                ArchiveMode::Prunable,
                "prunable",
                "prunable_delayed",
                "prunable_reopen",
            ),
            (
                ArchiveMode::Immutable,
                "immutable",
                "immutable_delayed",
                "immutable_reopen",
            ),
        ] {
            let configure = || {
                let mut config = config(&context, &committee);
                config.partition_prefix = format!("catalog_lqc_ordinal_crash_{label}");
                config.retention.lqc = mode;
                config
            };
            let first = Arc::new(lqc(&committee, 1, 0..5));
            let second = Arc::new(lqc(&committee, 1, 1..6));
            let first_id = first.id::<Sha256>();
            let second_id = second.id::<Sha256>();
            assert_ne!(first_id, second_id);

            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child(delayed_label),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(), delayed.child("catalog")).await;
            let current = client.checkpoint().await.unwrap();
            let record = Arc::new(
                TipRecord::at_tips(
                    current.history(),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let history = record.commitment::<Sha256>();
            assert_eq!(first.leader().history(), history);
            let checkpoint = |floor| {
                Checkpoint::try_from(CheckpointParts {
                    epoch: current.epoch(),
                    floor_generation: current.floor_generation(),
                    archive_layout: current.archive_layout(),
                    floor,
                    history,
                    history_index: Some(0),
                    ordered: current.ordered().to_vec(),
                    emitted: current.emitted().to_vec(),
                    committed: current.committed(),
                })
                .unwrap()
            };

            paths.0.lock().clear();
            syncs.arm();
            let token = client
                .start_commit(
                    Commit {
                        selected: vec![SelectedLqc {
                            view: first.view(),
                            id: first_id,
                            proof: Arc::clone(&first),
                        }],
                        history: vec![HistoryOpening {
                            commitment: history,
                            record: Arc::clone(&record),
                        }],
                        outputs: Vec::new(),
                        checkpoint: checkpoint(first_id),
                    },
                    Vec::new(),
                )
                .await
                .unwrap();
            let archive_syncs = syncs.calls();
            assert!(archive_syncs > 0);
            let mut publication = Box::pin(token.wait());
            wait_for_checkpoint_sync(&context, &syncs, &paths, &mut publication).await;
            drop(publication);
            handle.abort();
            drop(client);
            let _ = handle.await;

            let (client, handle, _delivery) =
                spawn_catalog(configure(), context.child(reopen_label)).await;
            assert_eq!(client.progress().await.unwrap().floor, current.floor());
            client
                .commit(Commit {
                    selected: vec![SelectedLqc {
                        view: second.view(),
                        id: second_id,
                        proof: Arc::clone(&second),
                    }],
                    history: vec![HistoryOpening {
                        commitment: history,
                        record: Arc::clone(&record),
                    }],
                    outputs: Vec::new(),
                    checkpoint: checkpoint(second_id),
                })
                .await
                .unwrap();
            assert!(client.final_lqc(first_id).await.unwrap());
            assert!(client.final_lqc(second_id).await.unwrap());
            client.prune(0).await.unwrap();
            assert_eq!(
                client.final_lqc(first_id).await.unwrap(),
                mode == ArchiveMode::Immutable
            );
            assert!(client.final_lqc(second_id).await.unwrap());
            drop(client);
            assert!(handle.await.is_ok());
        }
    });
}

#[test]
fn immutable_commit_recovers_canonical_body_and_reclaims_losing_candidates() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(31, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_IMMUTABLE_CLEANUP")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let genesis = committee.config.genesis();
        let record = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap(),
        );
        let history = record.commitment::<Sha256>();
        let canonical = producer_block(&committee, 0, 10);
        let losing = producer_block(&committee, 0, 11);
        let reference = canonical.reference();
        let losing_reference = losing.reference();

        let mut first = config(&context, &committee);
        first.retention.blocks = ArchiveMode::Immutable;
        let (delivery, _delivery_receiver) =
            delivery::channel(context.child("immutable_first_delivery"));
        let Opened {
            catalog: client,
            catalog_handle: handle,
            promoter,
            delivery_store: _,
        } = open_storage::<_, _, Sha256, _, _>(
            context.child("immutable_first"),
            &first,
            &first.actor_bounds().unwrap(),
            delivery,
        )
        .await
        .unwrap();
        let promoter_handle = promoter.map(|promoter| promoter.handle);
        client
            .admit_block(reference, Arc::clone(&canonical))
            .await
            .unwrap();
        client.admit_block(losing_reference, losing).await.unwrap();
        let mut emitted = genesis.tips().to_vec();
        emitted[0] = reference;
        client
            .commit(Commit {
                selected: Vec::new(),
                history: vec![HistoryOpening {
                    commitment: history,
                    record,
                }],
                outputs: vec![output_row(OutputIndex::ZERO, &canonical)],
                checkpoint: Checkpoint::try_from(CheckpointParts {
                    epoch: committee.config.epoch(),
                    floor_generation: 0,
                    archive_layout: Retention {
                        lqc: ArchiveMode::Prunable,
                        history: ArchiveMode::Immutable,
                        blocks: ArchiveMode::Immutable,
                    },
                    floor: genesis.lqc(),
                    history,
                    history_index: Some(0),
                    ordered: genesis.tips().to_vec(),
                    emitted,
                    committed: Some(OutputIndex::ZERO),
                })
                .unwrap(),
            })
            .await
            .unwrap();
        // The first promoter has not promoted, so the reopened one must redo the promotion.
        let metrics = context.encode();
        assert!(metrics.contains("immutable_first_promoter_promoted_output_count"));
        assert_eq!(
            metric_total(&metrics, "immutable_first_promoter_promoted_output_count"),
            0
        );
        handle.abort();
        promoter_handle.unwrap().abort();
        drop(client);
        let _ = handle.await;

        let mut reopened = config(&context, &committee);
        reopened.retention.blocks = ArchiveMode::Immutable;
        let (delivery, _delivery_receiver) =
            delivery::channel(context.child("immutable_reopen_delivery"));
        let Opened {
            catalog: client,
            catalog_handle: handle,
            promoter,
            delivery_store: _,
        } = open_storage::<_, _, Sha256, _, _>(
            context.child("immutable_reopen"),
            &reopened,
            &reopened.actor_bounds().unwrap(),
            delivery,
        )
        .await
        .unwrap();
        let (promoter, promoter_handle) = match promoter {
            Some(promoter) => (Some(promoter.mailbox), Some(promoter.handle)),
            None => (None, None),
        };
        let bodies = Bodies::new(client.clone(), promoter);
        for _ in 0..100 {
            if client.block(losing_reference).await.unwrap().is_none() {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(
            bodies.block(reference).await.unwrap().as_deref(),
            Some(canonical.as_ref())
        );
        assert!(client.block(losing_reference).await.unwrap().is_none());
        let outputs = client
            .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
            .await
            .unwrap();
        assert_eq!(outputs[0].reference, reference);
        assert_eq!(
            bodies.materialize(&outputs).await.unwrap()[0].as_ref(),
            canonical.as_ref()
        );
        promoter_handle.unwrap().abort();
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[test]
fn promotion_advances_under_steady_lookups() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(32, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_PROMOTION_LOOKUPS")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..4)
            .map(|chain| producer_block(&committee, chain, 32 + u64::from(chain)))
            .collect::<Vec<_>>();
        let mut config = config(&context, &committee);
        config.retention.blocks = ArchiveMode::Immutable;
        let (delivery, _delivery_receiver) = delivery::channel(context.child("delivery"));
        let Opened {
            catalog: client,
            catalog_handle,
            promoter,
            delivery_store: _,
        } = open_storage::<_, _, Sha256, _, _>(
            context.child("promoting"),
            &config,
            &config.actor_bounds().unwrap(),
            delivery,
        )
        .await
        .unwrap();
        let promoter = promoter.unwrap();

        // Bursts of immutable lookups keep the promoter's mailbox busy throughout.
        let lookups = promoter.mailbox.clone();
        let missing = committee.config.genesis().tips()[0];
        let hammer = context.child("lookups").spawn(move |_| async move {
            loop {
                try_join_all((0..32).map(|_| lookups.block(missing)))
                    .await
                    .unwrap();
            }
        });
        for block in &blocks {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
            let current = client.checkpoint().await.unwrap();
            client
                .commit(output_commit(&current, [block]))
                .await
                .unwrap();
        }
        let promoted =
            |metrics: &str| metric_total(metrics, "promoting_promoter_promoted_output_count");
        for _ in 0..1000 {
            if promoted(&context.encode()) == 4 {
                break;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(promoted(&context.encode()), 4);

        hammer.abort();
        promoter.handle.abort();
        drop(client);
        catalog_handle.abort();
    });
}

#[test]
fn reopen_replays_cleanup_owed_by_published_commits() {
    deterministic::Runner::default().start(|context| async move {
        let lifecycle = Lifecycle::new();
        let committee = &lifecycle.committee;
        let proof_id = lifecycle.proof.id::<Sha256>();
        let alternate_id = lifecycle.alternate.id::<Sha256>();
        let reference = lifecycle.block.reference();
        let conflicting = lifecycle.conflicting.reference();
        let (client, handle, _delivery) = open(&context, "first_open", committee).await;
        lifecycle.admit_all(&client).await;
        let stale_record = Arc::new(
            TipRecord::at_tips(
                Sha256::hash(&[b"stale pending history"]),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let stale_history = stale_record.commitment::<Sha256>();
        client
            .admit_history(View::new(2), stale_history, stale_record)
            .await
            .unwrap();
        client.commit(lifecycle.intermediate()).await.unwrap();
        assert!(client.lqc(alternate_id).await.unwrap().is_some());
        assert!(client.history(stale_history).await.unwrap().is_some());
        handle.abort();
        drop(client);
        let _ = handle.await;

        // An output-only commit leaves every pending candidate in place.
        let (client, handle, _delivery) = open(&context, "block_cleanup_recovery", committee).await;
        assert_eq!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await
                .unwrap()[0]
                .reference,
            reference
        );
        let wrong_context = BlockRef::new(ChainId::new(1), reference.height(), reference.digest());
        assert!(client.block(wrong_context).await.unwrap().is_none());
        assert_eq!(
            client.history(lifecycle.history).await.unwrap().as_deref(),
            Some(lifecycle.record.as_ref())
        );
        assert!(client.block(conflicting).await.unwrap().is_some());
        assert!(
            client
                .block(lifecycle.other_chain.reference())
                .await
                .unwrap()
                .is_some()
        );
        assert!(client.lqc(alternate_id).await.unwrap().is_some());
        assert!(client.history(stale_history).await.unwrap().is_some());
        client
            .admit_block(conflicting, lifecycle.conflicting.clone())
            .await
            .unwrap();
        client.commit(lifecycle.finalizing()).await.unwrap();
        // The cleanup is still owed when the catalog stops, so the next open replays it.
        assert!(client.lqc(alternate_id).await.unwrap().is_some());
        assert!(client.history(stale_history).await.unwrap().is_some());
        handle.abort();
        drop(client);
        let _ = handle.await;

        // The finalizing commit's cleanup prunes pending L-QCs and history at or below its view.
        let (client, handle, _delivery) =
            open(&context, "commit_cleanup_recovery", committee).await;
        assert_eq!(client.progress().await.unwrap().floor, proof_id);
        assert!(client.lqc(alternate_id).await.unwrap().is_none());
        assert!(client.history(stale_history).await.unwrap().is_none());
        assert!(client.block(conflicting).await.unwrap().is_some());
        handle.abort();
        drop(client);
        let _ = handle.await;

        // Replaying the cleanup again is harmless, and a replayed commit is accepted as published.
        let (client, handle, _delivery) = open(&context, "commit_cleanup_replay", committee).await;
        assert!(client.lqc(alternate_id).await.unwrap().is_none());
        assert!(client.history(stale_history).await.unwrap().is_none());
        assert!(client.block(conflicting).await.unwrap().is_some());
        client.commit(lifecycle.finalizing()).await.unwrap();
        assert!(
            client
                .block_by_digest(ChainId::new(1), reference.digest())
                .await
                .unwrap()
                .is_none(),
            "a finalized digest is served only for its producer chain"
        );
        assert_eq!(
            client.lqc(proof_id).await.unwrap().as_deref(),
            Some(lifecycle.proof.as_ref())
        );
        assert!(client.lqc(alternate_id).await.unwrap().is_none());
        assert!(client.latest_lqc().await.unwrap().is_none());
        drop(client);
        assert!(handle.await.is_ok());
    });
}
