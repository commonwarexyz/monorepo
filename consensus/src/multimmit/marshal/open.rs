//! Opening marshal storage and starting the actors that own it.
//!
//! Stores open in dependency order: the catalog's stores first, because the delivery cursor and
//! the promotion cursor are both seeded from the checkpoint they recover. An interrupted floor
//! installation stays pending until the delivery cursor has been opened against its target, and
//! only then is it completed.

use super::{
    actors::{catalog, delivery, promoter},
    config::{ActorBounds, ArchiveMode, Config, ConfigError},
    storage::{
        Error as StorageError,
        archive::{FinalBody, FinalizedArchive},
        catalog::CatalogStore,
        catalog_state::{CatalogState, Checkpoint},
        record::OnMissing,
    },
    types::{Cause, Failure},
};
use crate::multimmit::types::Body;
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::boxed;
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_storage::{Context, translator::Translator};
use std::num::NonZeroUsize;

/// Marshal storage could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The configuration is inconsistent.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A store failed to open or recover.
    #[error("marshal storage failed to open: {0}")]
    Storage(Failure),
    /// Delivery's durable cursor belongs to another generation than, or is ahead of, the
    /// recovered catalog checkpoint.
    #[error("delivery cursor does not match the recovered catalog checkpoint")]
    CursorMismatch,
}

impl From<StorageError> for OpenError {
    fn from(error: StorageError) -> Self {
        Self::Storage(Cause::Storage(error).into())
    }
}

/// The promoter's mailbox and task.
pub(super) struct Promoter<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) mailbox: promoter::Mailbox<H, B>,
    pub(super) handle: Handle<Result<(), promoter::Error>>,
}

/// Recovered storage, with the catalog and promoter running.
pub(super) struct Opened<E, H, V, B>
where
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) catalog: catalog::Mailbox<H, V, B>,
    pub(super) catalog_handle: Handle<Result<(), catalog::Fatal>>,
    /// The promoter, when finalized bodies move to an immutable archive.
    pub(super) promoter: Option<Promoter<H, B>>,
    /// Delivery's durable cursor, checked against the recovered checkpoint.
    pub(super) delivery_store: delivery::DeliveryCursor<E>,
}

/// Opens and recovers every catalog-owned store, the delivery cursor and the promotion cursor,
/// then starts the catalog and the promoter.
///
/// `delivery` is the mailbox of the delivery actor the caller starts later.
#[boxed]
pub(super) async fn storage<E, T, H, V, B>(
    context: E,
    config: &Config<T, V, B>,
    bounds: &ActorBounds,
    delivery: delivery::Mailbox<H, B>,
) -> Result<Opened<E, H, V, B>, OpenError>
where
    E: Clock + Context + Spawner,
    T: Translator,
    H: Hasher<Digest = B::Digest>,
    V: Variant,
    B: Codec + Digestible,
    B::Cfg: Clone,
{
    let mut stores = CatalogStore::<T, E, H, V, B>::open(&context, config).await?;
    let delivery_store = open_delivery(&context, config, stores.state()).await?;
    let promotion = match config.retention.blocks {
        ArchiveMode::Immutable => {
            Some(open_promotion(&context, config, stores.checkpoint()).await?)
        }
        ArchiveMode::Prunable => None,
    };
    stores.recover_install().await?;
    stores.recover_commit().await?;
    let checkpoint = stores.checkpoint().clone();
    if delivery_store.floor_generation() != checkpoint.floor_generation()
        || delivery_store.acknowledged() > checkpoint.committed()
    {
        return Err(OpenError::CursorMismatch);
    }

    let promotion = promotion.map(|store| {
        let (mailbox, receiver) = promoter::channel(
            context.child("promoter").child("mailbox"),
            NonZeroUsize::MIN,
        );
        (store, mailbox, receiver)
    });
    let (catalog, catalog_mailbox) = catalog::Catalog::new(catalog::Config {
        context: context.child("catalog"),
        stores,
        mailbox_size: bounds.catalog_mailbox,
        admission_cut_capacity: config.capacities.admission_cut_capacity,
        header_request_capacity: bounds.header_requests,
        custody_waiter_capacity: bounds.custody_waiters,
        body_waiter_capacity: bounds.body_waiters,
        materialization_capacity: bounds.body_reads,
        bounds: catalog::Bounds {
            max_commit_outputs: config.capacities.max_commit_outputs,
            max_commit_block_bytes: config.limits.max_commit_block_bytes,
            max_block_bytes: config.limits.max_block_bytes,
        },
        caches: catalog::CacheBounds {
            hot_bytes: config.limits.max_hot_block_bytes,
            materialized_bytes: config.limits.max_materialized_block_bytes,
        },
        delivery,
        promoter: promotion.as_ref().map(|(_, mailbox, _)| mailbox.clone()),
        acknowledged: delivery_store.acknowledged(),
    });
    let catalog_handle = catalog.start();
    let promoter = promotion.map(|(store, mailbox, receiver)| {
        let handle = promoter::Actor::new(promoter::Config {
            context: context.child("promoter"),
            catalog: catalog_mailbox.clone(),
            store,
            mailbox: receiver,
            committed: checkpoint.committed(),
            floor: promoter::PendingFloor {
                generation: checkpoint.floor_generation(),
                frontiers: checkpoint.emitted().to_vec(),
            },
            bounds: promoter::Bounds {
                max_items: config.capacities.max_commit_outputs,
                max_bytes: config.limits.max_commit_block_bytes,
            },
        })
        .start();
        Promoter { mailbox, handle }
    });
    Ok(Opened {
        catalog: catalog_mailbox,
        catalog_handle,
        promoter,
        delivery_store,
    })
}

/// Opens the delivery cursor against the catalog's recovery cut.
///
/// A pending installation owns the recovery cut, and a missing cursor may be created only where
/// it cannot skip committed output.
async fn open_delivery<E, T, V, B>(
    context: &E,
    config: &Config<T, V, B>,
    state: &CatalogState<B::Digest>,
) -> Result<delivery::DeliveryCursor<E>, StorageError>
where
    E: Context,
    T: Translator,
    V: Variant,
    B: Codec + Digestible,
{
    let recovery = state
        .install()
        .map_or_else(|| state.checkpoint(), |install| &install.checkpoint);
    let on_missing = if state.install().is_some() || state.checkpoint().committed().is_none() {
        OnMissing::Initialize
    } else {
        OnMissing::Reject
    };
    delivery::DeliveryCursor::init(
        context.child("delivery"),
        format!("{}_delivery", config.partition_prefix),
        on_missing,
        delivery::CatalogCut {
            generation: recovery.floor_generation(),
            committed: recovery.committed(),
        },
    )
    .await
}

/// Opens the immutable body archive and its promotion cursor.
///
/// Nothing committed means no promotion could have started, so a missing cursor is seeded from
/// the checkpoint.
async fn open_promotion<E, T, H, V, B>(
    context: &E,
    config: &Config<T, V, B>,
    checkpoint: &Checkpoint<H::Digest>,
) -> Result<promoter::PromotionStore<T, E, H, B>, StorageError>
where
    E: Context,
    T: Translator,
    H: Hasher<Digest = B::Digest>,
    V: Variant,
    B: Codec + Digestible,
    B::Cfg: Clone,
{
    let name = |suffix: &str| format!("{}_{suffix}", config.partition_prefix);
    let bodies: FinalBody<T, E, H, B> = FinalizedArchive::init_immutable(
        context.child("final_block_bodies"),
        config
            .archive
            .immutable(name("final_block_bodies"), config.body_codec_config.clone()),
    )
    .await?;
    let on_missing = if checkpoint.committed().is_none() {
        OnMissing::Initialize
    } else {
        OnMissing::Reject
    };
    promoter::PromotionStore::init(
        context.child("block_promotion"),
        bodies,
        name("block_promotion"),
        promoter::PromotionSeed {
            through: checkpoint.committed(),
            frontier: checkpoint.emitted_frontier().clone(),
            generation: checkpoint.floor_generation(),
        },
        on_missing,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Epochable as _, Viewable as _,
        multimmit::{
            marshal::{
                actors::catalog::Error as CatalogError,
                config::{ArchiveConfig, Retention, Start},
                storage::{
                    catalog_state::{CheckpointCodecConfig, CheckpointParts, PendingFloors},
                    commit::{Commit, HistoryOpening},
                    record::blob_size,
                },
                types::Floor,
            },
            mocks::Committee,
            types::{
                BlockRef, CertificateId, ChainId, CodecConfig, EpochGenesis, PathLimits, TipRecord,
                genesis_history,
            },
        },
        simplex::marshal::mocks::block::EmptyBlock,
        types::{Epoch, Height, View},
    };
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        metadata::{self, Metadata},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::Unit};
    use std::{error::Error as _, sync::Arc};

    type TestConfig = Config<TwoCap, MinPk, EmptyBlock<Sha256>>;
    type TestOpened = Opened<deterministic::Context, Sha256, MinPk, EmptyBlock<Sha256>>;

    const IMMUTABLE: Retention = Retention {
        lqc: ArchiveMode::Immutable,
        history: ArchiveMode::Immutable,
        blocks: ArchiveMode::Immutable,
    };

    fn genesis(epoch: Epoch, chains: u32) -> EpochGenesis<Sha256Digest> {
        let tips = (0..chains)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    Sha256::hash(&[&chain.to_be_bytes()]),
                )
            })
            .collect();
        EpochGenesis::new(
            epoch,
            Sha256::hash(&[b"leader"]),
            CertificateId::new(Sha256::hash(&[b"vqc"])),
            CertificateId::new(Sha256::hash(&[b"lqc"])),
            tips,
        )
        .unwrap()
    }

    fn archive(context: &deterministic::Context) -> ArchiveConfig<TwoCap> {
        ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        )
    }

    fn config(context: &deterministic::Context, epoch: Epoch, chains: u32) -> TestConfig {
        TestConfig::new(
            Start::Genesis(genesis(epoch, chains)),
            "marshal_open_test".into(),
            CodecConfig::new(5, chains as usize, PathLimits::new(4, 0).unwrap()).unwrap(),
            (),
            archive(context),
        )
    }

    /// Opens storage for `config` under `label` with a delivery mailbox nobody reads.
    async fn open(
        context: &deterministic::Context,
        label: &'static str,
        config: &TestConfig,
    ) -> Result<TestOpened, OpenError> {
        let (delivery, _receiver) = delivery::channel(context.child(label).child("delivery"));
        storage::<_, _, Sha256, _, _>(
            context.child(label),
            config,
            &config.actor_bounds()?,
            delivery,
        )
        .await
    }

    /// Stops the actors `open` started.
    async fn stop(opened: TestOpened) {
        let TestOpened {
            catalog,
            catalog_handle,
            promoter,
            ..
        } = opened;
        if let Some(promoter) = promoter {
            promoter.handle.abort();
            let _ = promoter.handle.await;
        }
        drop(catalog);
        assert!(catalog_handle.await.is_ok());
    }

    /// Returns the storage failure an open failed with.
    fn storage_failure(error: &OpenError) -> &StorageError {
        let OpenError::Storage(failure) = error else {
            panic!("open failed outside storage: {error}");
        };
        failure
            .source()
            .and_then(|source| source.downcast_ref::<StorageError>())
            .expect("a storage failure carries its storage error")
    }

    #[test]
    fn mailbox_capacity_is_independent_of_pending_storage_geometry() {
        deterministic::Runner::default().start(|context| async move {
            let mut original = config(&context, Epoch::new(7), 2);
            original.partition_prefix = "marshal_geometry_test".into();
            stop(open(&context, "original", &original).await.unwrap()).await;

            // Queue pressure is reconfigurable; persisted segment geometry is not.
            let mut resized = config(&context, Epoch::new(7), 2);
            resized.partition_prefix = "marshal_geometry_test".into();
            resized.capacities.catalog_mailbox_size = NZUsize!(8);
            resized.capacities.admission_cut_capacity = NZUsize!(8);
            stop(open(&context, "resized", &resized).await.unwrap()).await;

            let mut reshaped = config(&context, Epoch::new(7), 2);
            reshaped.partition_prefix = "marshal_geometry_test".into();
            reshaped.capacities.admission_cut_capacity = NZUsize!(512);
            reshaped.capacities.pending_segment_items = NZU64!(512);
            let Err(error) = open(&context, "reshaped", &reshaped).await else {
                panic!("pending segment geometry is namespace state");
            };
            assert!(matches!(
                storage_failure(&error),
                StorageError::Inconsistent("pending segment capacity differs from storage")
            ));
        });
    }

    #[test]
    fn invalid_configuration_is_rejected_before_storage_opens() {
        deterministic::Runner::default().start(|context| async move {
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.partition_prefix.clear();
            assert!(matches!(
                open(&context, "invalid", &invalid).await,
                Err(OpenError::Config(ConfigError::InvalidPartitionPrefix))
            ));
        });
    }

    #[test]
    fn fresh_namespace_rejects_checkpoint_larger_than_metadata_blob_bound() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = config(&context, Epoch::new(7), 2);
            config.limits.max_checkpoint_bytes = NZUsize!(1);
            let Err(error) = open(&context, "bounded", &config).await else {
                panic!("an oversized initial checkpoint must be rejected");
            };
            assert!(matches!(
                storage_failure(&error),
                StorageError::Invalid("initial catalog state exceeds max_checkpoint_bytes")
            ));
        });
    }

    #[test]
    fn oversized_commit_cleanup_is_rejected_before_finalized_writes() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(7);
            let genesis = genesis(epoch, 2);
            let initial = Checkpoint::try_from(CheckpointParts {
                epoch,
                floor_generation: 0,
                archive_layout: IMMUTABLE,
                floor: genesis.lqc(),
                history: genesis_history::<Sha256>(&genesis),
                history_index: None,
                ordered: genesis.tips().to_vec(),
                emitted: genesis.tips().to_vec(),
                committed: None,
            })
            .unwrap();
            let record =
                Arc::new(TipRecord::at_tips(initial.history(), genesis.tips().to_vec()).unwrap());
            let commitment = record.commitment::<Sha256>();
            let checkpoint = Checkpoint::try_from(CheckpointParts {
                epoch,
                floor_generation: 0,
                archive_layout: IMMUTABLE,
                floor: genesis.lqc(),
                history: commitment,
                history_index: Some(0),
                ordered: genesis.tips().to_vec(),
                emitted: genesis.tips().to_vec(),
                committed: None,
            })
            .unwrap();
            let ready_size = blob_size(&CatalogState::ready(checkpoint.clone(), None)).unwrap();
            assert!(
                blob_size(&CatalogState::committed(checkpoint.clone(), None, None)).unwrap()
                    > ready_size
            );

            let mut bounded = config(&context, epoch, 2);
            bounded.limits.max_checkpoint_bytes = NonZeroUsize::new(ready_size).unwrap();
            let opened = open(&context, "bounded_commit", &bounded).await.unwrap();
            assert!(matches!(
                opened
                    .catalog
                    .commit(Commit {
                        selected: Vec::new(),
                        history: vec![HistoryOpening {
                            commitment,
                            record: record.clone(),
                        }],
                        outputs: Vec::new(),
                        checkpoint,
                    })
                    .await,
                Err(CatalogError::Invalid(
                    "catalog state exceeds configured metadata bound"
                ))
            ));
            assert_eq!(opened.catalog.checkpoint().await.unwrap(), initial);
            assert!(opened.catalog.history(commitment).await.unwrap().is_none());
            stop(opened).await;

            let reopened = open(&context, "reopened_commit", &bounded).await.unwrap();
            assert_eq!(reopened.catalog.checkpoint().await.unwrap(), initial);
            assert!(
                reopened
                    .catalog
                    .history(commitment)
                    .await
                    .unwrap()
                    .is_none()
            );
            stop(reopened).await;
        });
    }

    #[test]
    fn trusted_start_floor_seeds_only_a_fresh_namespace() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(8, 6)
                .limits(PathLimits::new(4, 0).unwrap())
                .build();
            let genesis = committee.config.genesis();
            let history = Arc::new(
                TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap(),
            );
            let proof = Arc::new(committee.lqc(View::new(1)));
            assert_eq!(proof.leader().history(), history.commitment::<Sha256>());
            let make_config = |floor_generation| {
                TestConfig::new(
                    Start::Floor {
                        floor_generation,
                        floor: Box::new(Floor::new(
                            Arc::clone(&proof),
                            Arc::clone(&history),
                            genesis.tips().to_vec(),
                        )),
                    },
                    "marshal_trusted_floor_test".into(),
                    committee.codec(),
                    (),
                    archive(&context),
                )
            };
            assert_eq!(make_config(0).validate(), Err(ConfigError::FloorGeneration));
            let opened = open(&context, "marshal", &make_config(7)).await.unwrap();
            let checkpoint = opened.catalog.checkpoint().await.unwrap();
            assert_eq!(checkpoint.floor_generation(), 7);
            assert_eq!(checkpoint.floor(), proof.id::<Sha256>());
            assert_eq!(checkpoint.ordered(), genesis.tips());
            assert_eq!(checkpoint.emitted(), genesis.tips());
            stop(opened).await;
        });
    }

    #[test]
    fn interrupted_fresh_floor_seed_recovers_original_intent() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(8, 6)
                .limits(PathLimits::new(4, 0).unwrap())
                .build();
            let genesis = committee.config.genesis();
            let history =
                TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap();
            let original = committee.lqc(View::new(1));
            let replacement = committee.lqc(View::new(3));
            assert_eq!(original.leader().history(), history.commitment::<Sha256>());
            assert_eq!(
                replacement.leader().history(),
                history.commitment::<Sha256>()
            );
            let original_id = original.id::<Sha256>();
            let replacement_id = replacement.id::<Sha256>();
            assert_ne!(original_id, replacement_id);
            let prefix = "marshal_interrupted_floor_test";
            let max_checkpoint_bytes = NZUsize!(1024 * 1024);
            let checkpoint = Checkpoint::try_from(CheckpointParts {
                epoch: committee.config.epoch(),
                floor_generation: 7,
                archive_layout: IMMUTABLE,
                floor: original_id,
                history: history.commitment::<Sha256>(),
                history_index: Some(0),
                ordered: history.tips().to_vec(),
                emitted: genesis.tips().to_vec(),
                committed: None,
            })
            .unwrap();
            let initial = Checkpoint::try_from(CheckpointParts {
                epoch: committee.config.epoch(),
                floor_generation: 6,
                archive_layout: IMMUTABLE,
                floor: original.leader().parent(),
                history: history.parent(),
                history_index: None,
                ordered: history.tips().to_vec(),
                emitted: history.tips().to_vec(),
                committed: None,
            })
            .unwrap();
            let intent = CatalogState::ready(initial, None)
                .begin(
                    checkpoint.clone(),
                    original.view(),
                    None,
                    PendingFloors {
                        lqc: View::new(0),
                        history: View::new(0),
                        blocks: vec![Height::zero(); genesis.tips().len()],
                    },
                    original.encode(),
                    history.encode(),
                )
                .unwrap();
            let metadata: Metadata<_, Unit, CatalogState<Sha256Digest>> = Metadata::init(
                context.child("interrupted_intent"),
                metadata::Config {
                    partition: format!("{prefix}_checkpoint"),
                    codec_config: CheckpointCodecConfig::new(
                        committee.config.epoch(),
                        genesis.tips().len(),
                        max_checkpoint_bytes.get(),
                    ),
                },
            )
            .await
            .unwrap();
            drop(metadata.put_sync(Unit, intent).await.unwrap());

            let config = TestConfig::new(
                Start::Floor {
                    floor_generation: 8,
                    floor: Box::new(Floor::new(
                        Arc::new(replacement),
                        Arc::new(history.clone()),
                        genesis.tips().to_vec(),
                    )),
                },
                prefix.into(),
                committee.codec(),
                (),
                archive(&context),
            );
            let opened = open(&context, "recovered", &config).await.unwrap();
            assert_eq!(opened.catalog.checkpoint().await.unwrap(), checkpoint);
            assert_eq!(
                opened.catalog.lqc(original_id).await.unwrap().as_deref(),
                Some(&original)
            );
            assert!(opened.catalog.lqc(replacement_id).await.unwrap().is_none());
            stop(opened).await;
        });
    }

    #[test]
    fn reopen_rejects_changed_finalized_archive_modes() {
        deterministic::Runner::default().start(|context| async move {
            let mut original = config(&context, Epoch::new(9), 2);
            original.retention.lqc = ArchiveMode::Prunable;
            stop(open(&context, "original", &original).await.unwrap()).await;

            let changed = config(&context, Epoch::new(9), 2);
            let Err(error) = open(&context, "changed", &changed).await else {
                panic!("archive backend selection is namespace state");
            };
            assert!(matches!(
                storage_failure(&error),
                StorageError::Invalid(
                    "finalized archive modes do not match the existing namespace"
                )
            ));
        });
    }
}
