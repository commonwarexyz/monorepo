//! Floor installation and the delivery resets it drives.

use super::*;
use crate::multimmit::testing::expect_within;

#[test]
fn delivery_reset_preempts_cold_materialization() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(84, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COLD_RESET")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("delayed"),
            pending: reads.clone(),
        };
        let mut config = config(&context, &committee);
        config.limits.max_hot_block_bytes =
            NonZeroUsize::new(delivery::descriptor_bytes::<Sha256Digest>() as usize).unwrap();
        let bounds = delivery::Bounds {
            pending_acks: config.capacities.max_pending_acks,
            delivery_bytes: config.limits.max_delivery_bytes,
            hot_block_bytes: config.limits.max_hot_block_bytes,
        };
        let (delivery_client, commands) = delivery::channel(delayed.child("delivery_mailbox"));
        let control = delivery_client.clone();
        let Opened {
            catalog: client,
            catalog_handle,
            promoter: _,
            delivery_store: store,
        } = open_storage::<_, _, Sha256, _, _>(
            delayed.child("catalog"),
            &config,
            &config.actor_bounds().unwrap(),
            delivery_client,
        )
        .await
        .unwrap();
        let block = producer_block(&committee, 0, 84);
        client
            .admit_block(block.reference(), block.clone())
            .await
            .unwrap();
        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, [&block]))
            .await
            .unwrap();
        let gate = reads.arm();
        let reporter = TestReporter::default();
        let delivery_handle = delivery::Actor::new(delivery::Config {
            context: delayed.child("delivery"),
            store,
            catalog: client.clone(),
            bodies: Bodies::new(client.clone(), None),
            application: reporter.clone(),
            mailbox: commands,
            bounds,
        })
        .start();
        gate.blocked.await.unwrap();
        let reset = control
            .reset(current.floor_generation(), Some(OutputIndex::ZERO))
            .unwrap();
        select! {
            applied = reset.wait() => assert!(matches!(applied, Err(Error::DeliveryClosed))),
            _ = context.sleep(std::time::Duration::from_millis(10)) => {
                panic!("delivery reset waited for a superseded cold read");
            },
        }
        gate.release.send(()).unwrap();
        for _ in 0..10 {
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(!reporter.contains(OutputIndex::ZERO));
        assert_eq!(client.progress().await.unwrap().acknowledged, None);
        assert!(delivery_handle.await.unwrap().is_err());
        drop(control);
        drop(client);
        assert!(catalog_handle.await.is_ok());
    });
}

#[test]
fn floor_install_supersedes_queued_committed_body_read() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(85, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_INSTALL")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let blocks = (0..2)
            .map(|chain| producer_block(&committee, chain, 85 + u64::from(chain)))
            .collect::<Vec<_>>();
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let mut config = config(&context, &committee);
        config.capacities.max_commit_outputs = NZUsize!(2);
        config.capacities.max_pending_acks = NZUsize!(1);
        let descriptor = usize::try_from(delivery::descriptor_bytes::<Sha256Digest>()).unwrap();
        config.limits.max_hot_block_bytes =
            NonZeroUsize::new(blocks[0].encode_size() + descriptor).unwrap();
        let bounds = delivery::Bounds {
            pending_acks: config.capacities.max_pending_acks,
            delivery_bytes: config.limits.max_delivery_bytes,
            hot_block_bytes: config.limits.max_hot_block_bytes,
        };
        let (delivery_client, commands) = delivery::channel(delayed.child("delivery_mailbox"));
        let actor_bounds = config.actor_bounds().unwrap();
        let Opened {
            catalog: client,
            catalog_handle,
            promoter: _,
            delivery_store: store,
        } = drive_pending_syncs(
            &syncs,
            open_storage::<_, _, Sha256, _, _>(
                delayed.child("catalog"),
                &config,
                &actor_bounds,
                delivery_client,
            ),
        )
        .await
        .unwrap();
        let reporter = TestReporter::default();
        let delivery_handle = delivery::Actor::new(delivery::Config {
            context: delayed.child("delivery"),
            store,
            catalog: client.clone(),
            bodies: Bodies::new(client.clone(), None),
            application: reporter.clone(),
            mailbox: commands,
            bounds,
        })
        .start();
        drive_pending_syncs(&syncs, client.stage_blocks(&blocks))
            .await
            .unwrap();
        let current = client.checkpoint().await.unwrap();
        let batch = output_commit(&current, &blocks);
        let emitted = batch.checkpoint.emitted().to_vec();
        let handoff = vec![hot_output(
            OutputIndex::ZERO,
            &blocks[0],
            current.floor_generation(),
        )];
        let token = drive_pending_syncs(&syncs, client.start_commit(batch, handoff))
            .await
            .unwrap();
        drive_pending_syncs(&syncs, token.wait()).await.unwrap();
        wait_for_report(&context, &reporter, OutputIndex::ZERO).await;

        let genesis = committee.config.genesis();
        let base = TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
            .unwrap();
        let record = Arc::new(
            TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
        );
        let leader = committee.leader_block_with_parent(View::new(5), &committee.vqc(View::new(3)));
        let votes = (0..committee.codec().view_quorum())
            .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
            .collect::<Vec<_>>();
        let proof = Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                .unwrap(),
        );
        let target = checkpoint(
            &committee,
            1,
            proof.id::<Sha256>(),
            record.commitment::<Sha256>(),
            0,
            emitted,
            Some(OutputIndex::new(1)),
        );

        syncs.arm();
        let staged = client
            .stage_block(producer_block(&committee, 2, 87))
            .await
            .unwrap();
        client.progress().await.unwrap();
        assert!(syncs.calls() > 0);
        let mut install = Box::pin(client.install(InstallRequest {
            checkpoint: target,
            floors: install_floors(proof.view()),
            proof,
            history: record,
        }));
        select! {
            _ = &mut install => panic!("installation overtook admission durability"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
        assert!(reporter.acknowledge(OutputIndex::ZERO));
        context.sleep(std::time::Duration::from_millis(1)).await;
        assert!(!reporter.contains(OutputIndex::new(1)));
        syncs.unblock();
        expect_within(
            &context,
            std::time::Duration::from_secs(1),
            &mut install,
            "installation did not reset the pending cold read",
        )
        .await
        .unwrap();
        staged.wait().await.unwrap();
        let progress = client.progress().await.unwrap();
        assert_eq!(progress.floor_generation, 1);
        assert_eq!(progress.acknowledged, Some(OutputIndex::new(1)));
        assert!(!reporter.contains(OutputIndex::new(1)));
        delivery_handle.abort();
        let _ = delivery_handle.await;
        drop(install);
        drop(client);
        assert!(catalog_handle.await.is_ok());
    });
}

#[test]
fn queued_generation_reset_preempts_acknowledgement_refill() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(64, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_DELIVERY_RESET_PREEMPTION")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let mut config = config(&context, &committee);
        config.capacities.max_commit_outputs = NZUsize!(2);
        config.capacities.max_pending_acks = NZUsize!(1);
        let (delivery_client, delivery_commands) =
            delivery::channel(context.child("delivery_mailbox"));
        let delivery_control = delivery_client.clone();
        let (client, catalog_handle, reporter, delivery_handle) =
            spawn_catalog_delivery(config, &context, delivery_client, delivery_commands).await;

        let blocks = (0..2)
            .map(|chain| producer_block(&committee, chain, 64 + u64::from(chain)))
            .collect::<Vec<_>>();
        client.stage_blocks(&blocks).await.unwrap();
        let current = client.checkpoint().await.unwrap();
        client
            .commit(output_commit(&current, &blocks))
            .await
            .unwrap();

        wait_for_report(&context, &reporter, OutputIndex::ZERO).await;
        let reset = delivery_control.reset(1, None).unwrap();
        assert!(reporter.acknowledge(OutputIndex::ZERO));
        let mut reset = Box::pin(reset.wait());
        let mut next_report = Box::pin(wait_for_report(&context, &reporter, OutputIndex::new(1)));
        commonware_macros::select! {
            applied = &mut reset => assert!(matches!(applied, Err(Error::DeliveryClosed))),
            _ = &mut next_report => {
                panic!("delivery refilled before applying a queued generation reset")
            },
        }
        assert!(!reporter.contains(OutputIndex::new(1)));

        let _ = delivery_handle.await;
        drop(delivery_control);
        drop(client);
        assert!(catalog_handle.await.is_ok());
    });
}

#[test]
fn oversized_install_intent_is_rejected_before_archive_mutation() {
    deterministic::Runner::default().start(|context| async move {
        let limits = PathLimits::new(2, 2).unwrap();
        let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
        let committee = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INSTALL_BOUND")
            .producers(producers)
            .limits(limits)
            .build();
        let genesis = committee.config.genesis();
        let base = TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
            .unwrap();
        let record = Arc::new(
            TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
        );
        let history = record.commitment::<Sha256>();
        let parent = committee.vqc(View::new(3));
        let leader = committee.leader_block_with_parent(View::new(5), &parent);
        let votes = (0..committee.codec().view_quorum())
            .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
            .collect::<Vec<_>>();
        let proof = Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                .unwrap(),
        );
        assert_eq!(proof.leader().history(), history);
        let id = proof.id::<Sha256>();
        let target = checkpoint(&committee, 1, id, history, 0, genesis.tips().to_vec(), None);
        let prune = PendingFloors {
            lqc: View::new(proof.view().get() + 1),
            history: View::new(proof.view().get() + 1),
            blocks: vec![Height::new(1); 4],
        };
        let current = Checkpoint::try_from(CheckpointParts {
            epoch: committee.config.epoch(),
            floor_generation: 0,
            archive_layout: Retention {
                lqc: ArchiveMode::Prunable,
                history: ArchiveMode::Immutable,
                blocks: ArchiveMode::Prunable,
            },
            floor: genesis.lqc(),
            history: genesis_history::<Sha256>(genesis),
            history_index: None,
            ordered: genesis.tips().to_vec(),
            emitted: genesis.tips().to_vec(),
            committed: None,
        })
        .unwrap();
        let ready = CatalogState::ready(current, None);
        let intent = ready
            .begin(
                target.clone(),
                proof.view(),
                None,
                prune.clone(),
                commonware_codec::Encode::encode(proof.as_ref()),
                commonware_codec::Encode::encode(record.as_ref()),
            )
            .unwrap();
        let ready_size = blob_size(&ready).unwrap();
        let intent_size = blob_size(&intent).unwrap();
        assert!(ready_size < intent_size);
        let bound = NonZeroUsize::new(intent_size - 1).unwrap();
        assert!(ready_size <= bound.get());

        let mut bounded = config(&context, &committee);
        bounded.limits.max_checkpoint_bytes = bound;
        let (client, handle, _delivery) = spawn_catalog(bounded, context.child("bounded")).await;
        assert!(matches!(
            client
                .install(InstallRequest {
                    checkpoint: target,
                    floors: prune,
                    proof,
                    history: record,
                })
                .await,
            Err(Error::Invalid(
                "catalog state exceeds configured metadata bound"
            ))
        ));
        assert_eq!(client.progress().await.unwrap().floor_generation, 0);
        assert!(client.lqc(id).await.unwrap().is_none());
        assert!(client.history(history).await.unwrap().is_none());
        drop(client);
        assert!(handle.await.is_ok());

        let mut bounded = config(&context, &committee);
        bounded.limits.max_checkpoint_bytes = bound;
        let (client, handle, _delivery) = spawn_catalog(bounded, context.child("reopen")).await;
        assert_eq!(client.progress().await.unwrap().floor_generation, 0);
        assert!(client.lqc(id).await.unwrap().is_none());
        assert!(client.history(history).await.unwrap().is_none());
        drop(client);
        assert!(handle.await.is_ok());
    });
}

#[test]
fn floor_install_resets_delivery_then_prunes_the_old_generation() {
    deterministic::Runner::default().start(|context| async move {
        let lifecycle = Lifecycle::new();
        let committee = &lifecycle.committee;
        let proof_id = lifecycle.proof.id::<Sha256>();
        let reference = lifecycle.block.reference();
        lifecycle.acknowledged(&context, "acknowledged").await;
        let (client, handle, mut delivery) = open(&context, "install", committee).await;

        let parent = committee.vqc(View::new(3));
        let leader = committee.leader_block_with_parent(View::new(5), &parent);
        let votes = (0..committee.codec().view_quorum())
            .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
            .collect::<Vec<_>>();
        let floor_proof = Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                .unwrap(),
        );
        let floor_id = floor_proof.id::<Sha256>();
        let floor_record = Arc::new(
            TipRecord::at_tips(
                lifecycle.history,
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let floor_history = floor_record.commitment::<Sha256>();
        assert_eq!(floor_proof.leader().history(), floor_history);
        let request = |checkpoint| InstallRequest {
            checkpoint,
            floors: install_floors(floor_proof.view()),
            proof: floor_proof.clone(),
            history: floor_record.clone(),
        };
        let installed = checkpoint(
            committee,
            1,
            floor_id,
            floor_history,
            1,
            lifecycle.emitted(),
            Some(OutputIndex::ZERO),
        );
        let stale_history_index = checkpoint(
            committee,
            1,
            floor_id,
            floor_history,
            0,
            lifecycle.emitted(),
            Some(OutputIndex::ZERO),
        );
        assert!(matches!(
            client.install(request(stale_history_index)).await,
            Err(error) if error.is_rejected()
        ));
        let phantom_output = checkpoint(
            committee,
            1,
            floor_id,
            floor_history,
            1,
            lifecycle.emitted(),
            Some(OutputIndex::new(1)),
        );
        assert!(matches!(
            client.install(request(phantom_output)).await,
            Err(error) if error.is_rejected()
        ));

        let mut installation = Box::pin(client.install(request(installed.clone())));
        let reset = select! {
            result = &mut installation => {
                panic!("floor installation returned before delivery reset: {result:?}")
            },
            reset = next_reset(&mut delivery) => reset,
        };
        let delivery::Message::Reset {
            floor_generation,
            acknowledged,
            waiters: reset,
        } = reset
        else {
            unreachable!("next_reset returns a reset");
        };
        assert_eq!(floor_generation, 1);
        assert_eq!(acknowledged, Some(OutputIndex::ZERO));
        assert_eq!(reset.len(), 1);
        client
            .reset_delivery_cursor(floor_generation, acknowledged)
            .await
            .unwrap();
        for acknowledgement in reset {
            let _ = acknowledgement.send(Ok(()));
        }
        installation.await.unwrap();
        assert_eq!(
            client.progress().await.unwrap(),
            MarshalProgress {
                floor_generation: 1,
                floor: floor_id,
                committed: Some(OutputIndex::ZERO),
                acknowledged: Some(OutputIndex::ZERO),
            }
        );
        assert_eq!(
            client.lqc(floor_id).await.unwrap().as_deref(),
            Some(floor_proof.as_ref())
        );
        assert!(client.latest_lqc().await.unwrap().is_none());
        assert!(client.lqc(proof_id).await.unwrap().is_some());
        assert_eq!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await
                .unwrap()[0]
                .reference,
            reference
        );
        assert_eq!(
            client.history(floor_history).await.unwrap().as_deref(),
            Some(floor_record.as_ref())
        );
        assert!(matches!(
            client.install(request(installed)).await,
            Err(error) if error.is_rejected()
        ));

        // Pruning the new generation reclaims every artifact of the old one.
        assert!(matches!(client.prune(0).await, Err(error) if error.is_rejected()));
        client.prune(1).await.unwrap();
        client.prune(1).await.unwrap();
        assert!(client.lqc(proof_id).await.unwrap().is_none());
        assert!(client.block(reference).await.unwrap().is_none());
        assert!(
            client
                .block(lifecycle.other_chain.reference())
                .await
                .unwrap()
                .is_none()
        );

        // The committed row is gone with its generation, so reading it stops the catalog.
        assert!(matches!(
            client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await,
            Err(Error::Closed)
        ));
        assert!(matches!(
            handle.await,
            Ok(Err(Fatal::Storage(StorageError::Inconsistent(_))))
        ));
        drop(client);

        let (client, handle, _delivery) = open(&context, "installed_reopen", committee).await;
        assert_eq!(client.progress().await.unwrap().floor, floor_id);
        assert_eq!(
            client.lqc(floor_id).await.unwrap().as_deref(),
            Some(floor_proof.as_ref())
        );
        assert_eq!(
            client.history(floor_history).await.unwrap().as_deref(),
            Some(floor_record.as_ref())
        );
        assert!(client.latest_lqc().await.unwrap().is_none());
        drop(client);
        assert!(handle.await.is_ok());
    });
}
