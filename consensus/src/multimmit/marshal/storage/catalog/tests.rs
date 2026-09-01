//! Catalog store commit validation tests.

use super::{install::InstallArtifacts, *};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            actors::delivery,
            open::{Opened, storage as open_storage},
            storage::{
                commit::{Commit, CustodyRef, HistoryOpening, OutputRow, SelectedLqc},
                record::blob_size,
            },
        },
        mocks::Committee,
        testing::TestBody,
        types::{ChainId, PathLimits},
    },
    types::Participant,
};
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context as DeterministicContext},
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::future::try_join_all;
use rstest::rstest;
use std::num::NonZeroUsize;
type TestStore = CatalogStore<TwoCap, DeterministicContext, Sha256, MinPk, TestBody>;
type TestConfig = Config<TwoCap, MinPk, TestBody>;

fn committee(namespace: &[u8]) -> Committee<MinPk> {
    Committee::builder(7, 6)
        .namespace(namespace)
        .producers((0..4).map(Participant::new).collect())
        .limits(PathLimits::new(2, 2).unwrap())
        .build()
}

fn config(
    context: &DeterministicContext,
    committee: &Committee<MinPk>,
    prefix: &str,
) -> TestConfig {
    let mut archive = ArchiveConfig::new(
        TwoCap,
        CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
    );
    archive.items_per_section = NZU64!(1);
    let mut config = Config::new(
        Start::Genesis(committee.config.genesis().clone()),
        prefix.into(),
        committee.codec(),
        (),
        archive,
    );
    config.retention.lqc = ArchiveMode::Prunable;
    config.retention.history = ArchiveMode::Immutable;
    config.retention.blocks = ArchiveMode::Prunable;
    config
}

/// Opens the store and completes any recovery its record owes, as the catalog does at start.
async fn open(
    context: &DeterministicContext,
    label: &'static str,
    config: &TestConfig,
) -> TestStore {
    let mut store = Box::pin(TestStore::open(&context.child(label), config))
        .await
        .unwrap();
    Box::pin(store.recover_install()).await.unwrap();
    Box::pin(store.recover_commit()).await.unwrap();
    store
}

/// Admits one pending L-QC and waits until its admission cut is durable.
async fn admit_lqc(store: &mut TestStore, proof: &Arc<Lqc<MinPk, Sha256Digest>>) {
    let admission = Admission::Lqc(proof.view(), proof.id::<Sha256>(), Arc::clone(proof));
    let footprint = store
        .admission_footprint(&[StagedAdmission {
            admission: Admission::Lqc(proof.view(), proof.id::<Sha256>(), Arc::clone(proof)),
            durable: true,
        }])
        .unwrap()
        .unwrap();
    let mut writes = std::iter::once(admission).peekable();
    let write = store.start_admission(&mut writes).unwrap().unwrap();
    let write = write.await.unwrap();
    store.finish_admission(write).unwrap();
    try_join_all(store.start_admission_sync(footprint).await.unwrap())
        .await
        .unwrap();
}

fn genesis_checkpoint(committee: &Committee<MinPk>) -> Checkpoint<Sha256Digest> {
    let genesis = committee.config.genesis();
    Checkpoint::try_from(CheckpointParts {
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
    .unwrap()
}

/// Returns the parts of `checkpoint`, for building a successor.
fn parts(checkpoint: &Checkpoint<Sha256Digest>) -> CheckpointParts<Sha256Digest> {
    CheckpointParts {
        epoch: checkpoint.epoch(),
        floor_generation: checkpoint.floor_generation(),
        archive_layout: checkpoint.archive_layout(),
        floor: checkpoint.floor(),
        history: checkpoint.history(),
        history_index: checkpoint.history_index(),
        ordered: checkpoint.ordered().to_vec(),
        emitted: checkpoint.emitted().to_vec(),
        committed: checkpoint.committed(),
    }
}

/// The artifacts of the commit that the commit crash-cut test interrupts.
struct CommitFixture {
    proof: Arc<Lqc<MinPk, Sha256Digest>>,
    stale: Arc<Lqc<MinPk, Sha256Digest>>,
    record: Arc<TipRecord<Sha256Digest>>,
    initial: Checkpoint<Sha256Digest>,
    committed: Checkpoint<Sha256Digest>,
}

impl CommitFixture {
    fn new() -> Self {
        let alternate = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_COMMIT_CUT_OTHER");
        let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_COMMIT_CUT");
        let genesis = committee.config.genesis();
        let record = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap(),
        );
        let proof = Arc::new(committee.lqc(View::new(3)));
        let initial = genesis_checkpoint(&committee);
        let committed = Checkpoint::try_from(CheckpointParts {
            floor: proof.id::<Sha256>(),
            history: record.commitment::<Sha256>(),
            history_index: Some(0),
            ..parts(&initial)
        })
        .unwrap();
        Self {
            proof,
            stale: Arc::new(alternate.lqc(View::new(3))),
            record,
            initial,
            committed,
        }
    }
}

/// A crash point in the checkpoint-last commit protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CommitCut {
    Buffered,
    ArchivesSynced,
    Published,
    CleanedUp,
}

#[rstest]
fn commit_crash_cuts_recover_the_last_published_checkpoint(
    #[values(
        CommitCut::Buffered,
        CommitCut::ArchivesSynced,
        CommitCut::Published,
        CommitCut::CleanedUp
    )]
    cut: CommitCut,
) {
    let prefix = "storage_commit_cut";
    let (fixture, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_COMMIT_CUT");
            let config = config(&context, &committee, prefix);
            let fixture = CommitFixture::new();
            let history = fixture.record.commitment::<Sha256>();

            let mut store = open(&context, "first", &config).await;
            assert_eq!(store.checkpoint(), &fixture.initial);
            admit_lqc(&mut store, &fixture.stale).await;
            let publication = store
                .buffer_commit(Commit {
                    selected: vec![SelectedLqc {
                        view: fixture.proof.view(),
                        id: fixture.proof.id::<Sha256>(),
                        proof: Arc::clone(&fixture.proof),
                    }],
                    history: vec![HistoryOpening {
                        commitment: history,
                        record: Arc::clone(&fixture.record),
                    }],
                    outputs: Vec::new(),
                    checkpoint: fixture.committed.clone(),
                })
                .await
                .unwrap();
            assert_eq!(store.checkpoint(), &fixture.initial);
            if cut >= CommitCut::ArchivesSynced {
                try_join_all(store.start_finalized_sync(&publication).await.unwrap())
                    .await
                    .unwrap();
            }
            if cut >= CommitCut::Published {
                store
                    .start_sync_publication(&publication)
                    .await
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(store.checkpoint(), &fixture.committed);
            }
            if cut >= CommitCut::CleanedUp {
                store.cleanup_pending(publication.cleanup).await.unwrap();
                assert!(
                    store
                        .lqc(fixture.stale.id::<Sha256>())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            fixture
        });

    // Unsynced writes are lost, as in a real crash.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_COMMIT_CUT");
        let config = config(&context, &committee, prefix);
        let CommitFixture {
            proof,
            stale,
            record,
            initial,
            committed,
        } = fixture;
        let proof_id = proof.id::<Sha256>();
        let stale_id = stale.id::<Sha256>();
        let history = record.commitment::<Sha256>();

        let store = open(&context, "recovered", &config).await;
        if cut >= CommitCut::Published {
            assert_eq!(store.checkpoint(), &committed);
            assert_eq!(
                store.lqc(proof_id).await.unwrap().as_deref(),
                Some(proof.as_ref())
            );
            assert!(store.final_lqc(proof_id).await.unwrap());
            assert_eq!(
                store.history(history).await.unwrap().as_deref(),
                Some(record.as_ref())
            );
            assert!(store.lqc(stale_id).await.unwrap().is_none());
            assert_eq!(
                store.state().commit_cleanup(),
                Some(CommitCleanup {
                    selected: Some(proof.view()),
                })
            );
        } else {
            assert_eq!(store.checkpoint(), &initial);
            assert_eq!(
                store.lqc(stale_id).await.unwrap().as_deref(),
                Some(stale.as_ref())
            );
            assert!(store.state().commit_cleanup().is_none());
        }
    });
}

/// The artifacts of the floor installation that the install crash-cut test interrupts.
struct InstallFixture {
    proof: Arc<Lqc<MinPk, Sha256Digest>>,
    record: Arc<TipRecord<Sha256Digest>>,
    target: Checkpoint<Sha256Digest>,
}

impl InstallFixture {
    fn new(committee: &Committee<MinPk>) -> Self {
        let genesis = committee.config.genesis();
        let base = TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
            .unwrap();
        let record = Arc::new(
            TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
        );
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
        assert_eq!(proof.leader().history(), record.commitment::<Sha256>());
        let target = Checkpoint::try_from(CheckpointParts {
            floor_generation: 1,
            floor: proof.id::<Sha256>(),
            history: record.commitment::<Sha256>(),
            history_index: Some(0),
            ..parts(&genesis_checkpoint(committee))
        })
        .unwrap();
        Self {
            proof,
            record,
            target,
        }
    }
}

/// A crash point in the floor installation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum InstallCut {
    Begun,
    Archived,
    Finished,
}

#[rstest]
fn install_crash_cuts_recover_the_installed_floor(
    #[values(InstallCut::Begun, InstallCut::Archived, InstallCut::Finished)] cut: InstallCut,
) {
    let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_INSTALL_CUT";
    let prefix = "storage_install_cut";
    let (fixture, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let committee = committee(namespace);
            let config = config(&context, &committee, prefix);
            let fixture = InstallFixture::new(&committee);
            let InstallFixture {
                proof,
                record,
                target,
            } = &fixture;
            let initial = genesis_checkpoint(&committee);
            let floors = PendingFloors {
                lqc: View::new(proof.view().get() + 1),
                history: View::new(proof.view().get() + 1),
                blocks: vec![Height::new(1); 4],
            };
            let pending = Arc::new(committee.lqc(View::new(2)));

            let mut store = open(&context, "first", &config).await;
            admit_lqc(&mut store, &pending).await;
            store
                .begin_install(target.clone(), floors, proof, record)
                .await
                .unwrap();
            assert_eq!(store.checkpoint(), &initial);
            assert_eq!(
                store.state().install().map(|install| &install.checkpoint),
                Some(target)
            );
            if cut >= InstallCut::Archived {
                store
                    .archive_install(
                        target,
                        InstallArtifacts {
                            proof: Arc::clone(proof),
                            history: Arc::clone(record),
                        },
                    )
                    .await
                    .unwrap();
            }
            if cut >= InstallCut::Finished {
                store.finish_install().await.unwrap();
                assert_eq!(store.checkpoint(), target);
            }
            fixture
        });

    // Unsynced writes are lost, as in a real crash.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let committee = committee(namespace);
        let config = config(&context, &committee, prefix);
        let InstallFixture {
            proof,
            record,
            target,
        } = fixture;
        let id = proof.id::<Sha256>();
        let history = record.commitment::<Sha256>();

        let store = open(&context, "recovered", &config).await;
        assert_eq!(store.checkpoint(), &target);
        assert!(store.state().install().is_none());
        assert_eq!(store.state().lqc_index(), Some(proof.view().get()));
        assert_eq!(
            store.lqc(id).await.unwrap().as_deref(),
            Some(proof.as_ref())
        );
        assert_eq!(
            store.history(history).await.unwrap().as_deref(),
            Some(record.as_ref())
        );
        assert!(store.latest_lqc().await.unwrap().is_none());
    });
}

#[test]
fn oversized_commit_record_is_rejected_before_any_write() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_COMMIT_BOUND");
        let initial = genesis_checkpoint(&committee);
        let ready = blob_size(&CatalogState::ready(initial.clone(), None)).unwrap();
        let mut config = config(&context, &committee, "storage_commit_bound");
        config.limits.max_checkpoint_bytes = NonZeroUsize::new(ready).unwrap();
        let genesis = committee.config.genesis();
        let record = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap(),
        );
        let history = record.commitment::<Sha256>();
        let checkpoint = Checkpoint::try_from(CheckpointParts {
            history,
            history_index: Some(0),
            ..parts(&initial)
        })
        .unwrap();

        let mut store = open(&context, "bounded", &config).await;
        assert!(matches!(
            store
                .buffer_commit(Commit {
                    selected: Vec::new(),
                    history: vec![HistoryOpening {
                        commitment: history,
                        record,
                    }],
                    outputs: Vec::new(),
                    checkpoint,
                })
                .await,
            Err(Error::Invalid(
                "catalog state exceeds configured metadata bound"
            ))
        ));
        assert_eq!(store.checkpoint(), &initial);
        assert!(store.history(history).await.unwrap().is_none());
    });
}

/// Whether the delivery cursor exists when the catalog crashes during an install.
#[derive(Clone, Copy, Debug)]
enum CursorAtCrash {
    /// The marshal ran before the install, leaving a generation-zero cursor.
    Present,
    /// Only the catalog store ran, so no cursor was ever written.
    Missing,
}

/// Admits one block and waits until its admission cut is durable.
async fn admit_block(store: &mut TestStore, block: &Arc<TransactionBlock<Sha256, TestBody>>) {
    let footprint = store
        .admission_footprint(&[StagedAdmission {
            admission: Admission::Block(block.reference(), Arc::clone(block)),
            durable: true,
        }])
        .unwrap()
        .unwrap();
    let mut writes =
        std::iter::once(Admission::Block(block.reference(), Arc::clone(block))).peekable();
    let write = store.start_admission(&mut writes).unwrap().unwrap();
    let write = write.await.unwrap();
    store.finish_admission(write).unwrap();
    try_join_all(store.start_admission_sync(footprint).await.unwrap())
        .await
        .unwrap();
}

#[rstest]
fn restart_with_a_pending_install_seeds_the_delivery_cursor_at_the_install(
    #[values(CursorAtCrash::Present, CursorAtCrash::Missing)] cursor: CursorAtCrash,
) {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(b"_COMMONWARE_CONSENSUS_MULTIMMIT_STORAGE_INSTALL_RESTART");
        let prefix = "storage_install_restart";
        let genesis = committee.config.genesis();
        let base = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap(),
        );
        let base_history = base.commitment::<Sha256>();
        let body = TestBody::new(Sha256::hash(&[b"parent"]), Height::new(1), 10);
        let block = Arc::new(
            TransactionBlock::new(
                committee.transaction_header(ChainId::new(0), body.digest()),
                body,
            )
            .unwrap(),
        );
        let mut emitted = genesis.tips().to_vec();
        emitted[0] = block.reference();
        let committed = Checkpoint::try_from(CheckpointParts {
            history: base_history,
            history_index: Some(0),
            emitted,
            committed: Some(OutputIndex::ZERO),
            ..parts(&genesis_checkpoint(&committee))
        })
        .unwrap();
        let commit = || Commit {
            selected: Vec::new(),
            history: vec![HistoryOpening {
                commitment: base_history,
                record: Arc::clone(&base),
            }],
            outputs: vec![OutputRow::new(
                OutputIndex::ZERO,
                CustodyRef::for_test(&block),
            )],
            checkpoint: committed.clone(),
        };

        // Commit one output.
        match cursor {
            CursorAtCrash::Present => {
                let (delivery, _delivery) = delivery::channel(context.child("first_delivery"));
                let config = config(&context, &committee, prefix);
                let Opened {
                    catalog: client,
                    catalog_handle: handle,
                    promoter: _,
                    delivery_store: cursor,
                } = open_storage::<_, _, Sha256, _, _>(
                    context.child("first"),
                    &config,
                    &config.actor_bounds().unwrap(),
                    delivery,
                )
                .await
                .unwrap();
                assert_eq!(cursor.floor_generation(), 0);
                client
                    .admit_block(block.reference(), Arc::clone(&block))
                    .await
                    .unwrap();
                client.commit(commit()).await.unwrap();
                drop(cursor);
                drop(client);
                assert!(handle.await.is_ok());
            }
            CursorAtCrash::Missing => {
                let config = config(&context, &committee, prefix);
                let mut store = open(&context, "first", &config).await;
                admit_block(&mut store, &block).await;
                let publication = store.buffer_commit(commit()).await.unwrap();
                try_join_all(store.start_finalized_sync(&publication).await.unwrap())
                    .await
                    .unwrap();
                store
                    .start_sync_publication(&publication)
                    .await
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(store.checkpoint(), &committed);
            }
        }

        // Crash after the install intent is durable and before it is archived.
        let record = Arc::new(TipRecord::at_tips(base_history, genesis.tips().to_vec()).unwrap());
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
        let target = Checkpoint::try_from(CheckpointParts {
            floor_generation: 1,
            floor: proof.id::<Sha256>(),
            history,
            history_index: Some(1),
            ..parts(&committed)
        })
        .unwrap();
        let floors = PendingFloors {
            lqc: View::new(proof.view().get() + 1),
            history: View::new(proof.view().get() + 1),
            blocks: vec![Height::new(1); 4],
        };
        let config = config(&context, &committee, prefix);
        let mut store = open(&context, "intent", &config).await;
        store
            .begin_install(target.clone(), floors, &proof, &record)
            .await
            .unwrap();
        drop(store);

        // The pending install owns the recovery cut even though an output is committed, so the
        // cursor is created or reseeded at generation one before the install finishes.
        let (delivery, _delivery) = delivery::channel(context.child("restart_delivery"));
        let Opened {
            catalog: client,
            catalog_handle: handle,
            promoter: _,
            delivery_store: cursor,
        } = open_storage::<_, _, Sha256, _, _>(
            context.child("restart"),
            &config,
            &config.actor_bounds().unwrap(),
            delivery,
        )
        .await
        .unwrap();
        assert_eq!(cursor.floor_generation(), 1);
        assert_eq!(cursor.acknowledged(), Some(OutputIndex::ZERO));
        let progress = client.progress().await.unwrap();
        assert_eq!(progress.floor_generation, 1);
        assert_eq!(progress.floor, proof.id::<Sha256>());
        assert_eq!(progress.committed, Some(OutputIndex::ZERO));
        assert_eq!(progress.acknowledged, Some(OutputIndex::ZERO));
        assert_eq!(client.checkpoint().await.unwrap(), target);
        drop(cursor);
        drop(client);
        assert!(handle.await.is_ok());
    });
}
