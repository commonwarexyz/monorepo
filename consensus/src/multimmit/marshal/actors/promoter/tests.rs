//! Promoter actor tests: lookup fairness and publication ordering.

use super::{
    actor::{Actor, Bounds, Config as PromoterConfig, MESSAGES_PER_STEP, PendingFloor},
    mailbox::{Mailbox, Message, channel},
    store::{PromotionSeed, PromotionStore},
};
use crate::{
    multimmit::{
        marshal::{
            actors::{
                catalog,
                delivery::{self, HotOutput},
            },
            bodies::Bodies,
            config::{ArchiveConfig, Config, Start},
            open::{Opened, storage},
            storage::{
                archive::{FinalBody, FinalizedArchive},
                catalog::{CatalogStore, StoredRef},
                record::OnMissing,
            },
            types::OutputIndex,
        },
        mocks::Committee,
        testing::{SpanRecorder, TestBody},
        types::{BlockRef, ChainId, PathLimits, TransactionBlock, TransactionBlockHeader},
    },
    types::{Epoch, Height},
};
use commonware_actor::mailbox::Policy as _;
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZU16, NZUsize};
use futures::poll;
use std::{collections::VecDeque, sync::Arc};
use tracing::Instrument as _;
use tracing_subscriber::prelude::*;

#[test]
fn lookup_dequeue_preserves_each_caller() {
    let spans = SpanRecorder::default();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(spans.clone()), || {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(41, 6)
                .limits(PathLimits::new(1, 0).unwrap())
                .build();
            let config = Config::<_, MinPk, TestBody>::new(
                Start::Genesis(committee.config.genesis().clone()),
                "promoter_tracing".into(),
                committee.codec(),
                (),
                ArchiveConfig::new(
                    TwoCap,
                    CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8)),
                ),
            );
            let (delivery, _receiver) = delivery::channel(context.child("delivery"));
            let Opened {
                catalog,
                catalog_handle,
                promoter,
                ..
            } = storage::<_, _, Sha256, _, _>(
                context.child("catalog"),
                &config,
                &config.actor_bounds().unwrap(),
                delivery,
            )
            .await
            .unwrap();
            let promoter = promoter.expect("immutable block retention runs the promoter");
            let client = promoter.mailbox.clone();
            let reference = committee.config.genesis().tips()[0];
            let callers = [
                tracing::info_span!("first_lookup"),
                tracing::info_span!("second_lookup"),
            ];
            let first = client.block(reference).instrument(callers[0].clone());
            let second = client
                .blocks(vec![reference])
                .instrument(callers[1].clone());
            futures::pin_mut!(first, second);
            assert!(poll!(&mut first).is_pending());
            assert!(poll!(&mut second).is_pending());
            assert!(
                !spans
                    .spans()
                    .iter()
                    .any(|span| span.name.ends_with("lookup.process"))
            );
            assert!(first.await.unwrap().is_none());
            assert_eq!(second.await.unwrap().len(), 1);
            let processing = spans.named("multimmit.marshal.promoter.lookup.process");
            for caller in &callers {
                assert!(
                    processing
                        .iter()
                        .any(|span| span.parent == caller.id().map(|id| id.into_u64())),
                    "each dequeued lookup needs its own processing child"
                );
            }
            let bodies = Bodies::new(catalog, Some(client.clone()));
            assert!(
                bodies
                    .block_by_digest(reference.chain(), reference.digest())
                    .await
                    .unwrap()
                    .is_none()
            );
            let rpc = spans
                .first("multimmit.marshal.bodies.block_by_digest")
                .unwrap()
                .id;
            assert!(
                spans
                    .named("multimmit.marshal.promoter.lookup.process")
                    .iter()
                    .any(|span| span.parent == Some(rpc))
            );
            catalog_handle.abort();
            promoter.handle.abort();
        });
    });
}

/// Returns output `index` with its body in memory.
pub(super) fn hot_output(index: u64) -> HotOutput<Sha256, TestBody> {
    let body = TestBody::new(
        Sha256::hash(&[b"body parent"]),
        Height::new(index + 1),
        index,
    );
    let header = TransactionBlockHeader::new(
        Epoch::new(1),
        ChainId::new(0),
        Height::new(index + 1),
        Sha256::hash(&[b"producer parent", &index.to_be_bytes()]),
        body.digest(),
    )
    .unwrap();
    let block = Arc::new(TransactionBlock::<Sha256, _>::new(header, body).unwrap());
    HotOutput {
        stored: StoredRef {
            index: OutputIndex::new(index),
            reference: block.reference(),
            encoded_len: u64::try_from(block.encode_size()).unwrap(),
            floor_generation: 0,
        },
        block,
    }
}
pub(super) type TestCatalog = catalog::Catalog<
    deterministic::Context,
    TwoCap,
    deterministic::Context,
    Sha256,
    MinPk,
    TestBody,
>;
pub(super) type TestPromoter =
    Actor<deterministic::Context, TwoCap, deterministic::Context, Sha256, MinPk, TestBody>;

/// A promoter one output behind its target, over a catalog that never starts, so every promotion
/// step waits forever.
pub(super) struct Stalled {
    /// Keeps the catalog's receivers, and so the promoter's pending catalog requests, alive.
    pub(super) _catalog: TestCatalog,
    pub(super) mailbox: Mailbox<Sha256, TestBody>,
    pub(super) promoter: TestPromoter,
    /// A block no promotion has copied.
    pub(super) reference: BlockRef<Sha256Digest>,
}

pub(super) async fn stalled(context: &deterministic::Context, prefix: &'static str) -> Stalled {
    let committee = Committee::<MinPk>::builder(42, 6)
        .limits(PathLimits::new(1, 0).unwrap())
        .build();
    let config = Config::<_, MinPk, TestBody>::new(
        Start::Genesis(committee.config.genesis().clone()),
        prefix.into(),
        committee.codec(),
        (),
        ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        ),
    );
    let bounds = config.actor_bounds().unwrap();
    let stores = CatalogStore::<_, _, Sha256, MinPk, _>::open(&context.child("stores"), &config)
        .await
        .unwrap();
    let checkpoint = stores.checkpoint().clone();
    let (delivery, _delivery) = delivery::channel(context.child("delivery"));
    let (mailbox, receiver) = channel(context.child("promoter_mailbox"), NZUsize!(4));
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
        promoter: Some(mailbox.clone()),
        acknowledged: None,
    });
    let bodies: FinalBody<TwoCap, _, Sha256, TestBody> = FinalizedArchive::init_immutable(
        context.child("bodies"),
        config.archive.immutable(format!("{prefix}_bodies"), ()),
    )
    .await
    .unwrap();
    let store = PromotionStore::init(
        context.child("promotion"),
        bodies,
        format!("{prefix}_cursor"),
        PromotionSeed {
            through: None,
            frontier: checkpoint.emitted_frontier().clone(),
            generation: 0,
        },
        OnMissing::Initialize,
    )
    .await
    .unwrap();
    let promoter = Actor::new(PromoterConfig {
        context: context.child("promoter"),
        catalog: catalog_mailbox,
        store,
        mailbox: receiver,
        committed: Some(OutputIndex::new(1)),
        floor: PendingFloor {
            generation: 0,
            frontiers: checkpoint.emitted().to_vec(),
        },
        bounds: Bounds {
            max_items: NZUsize!(1),
            max_bytes: NZUsize!(1024),
        },
    });
    Stalled {
        _catalog: catalog,
        mailbox,
        promoter,
        reference: committee.config.genesis().tips()[0],
    }
}

#[test]
fn queued_lookups_run_before_the_next_promotion_step() {
    deterministic::Runner::default().start(|context| async move {
        let Stalled {
            _catalog,
            mailbox,
            promoter,
            reference,
        } = stalled(&context, "promoter_preemption").await;
        let first = mailbox.block(reference);
        let second = mailbox.blocks(vec![reference]);
        futures::pin_mut!(first, second);
        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut second).is_pending());
        let handle = promoter.start();
        assert!(first.await.unwrap().is_none());
        assert_eq!(second.await.unwrap(), vec![None]);
        handle.abort();
    });
}

#[test]
fn steady_lookups_cannot_hold_off_promotion() {
    deterministic::Runner::default().start(|context| async move {
        let Stalled {
            _catalog,
            mailbox,
            promoter,
            reference,
        } = stalled(&context, "promoter_starvation").await;
        let mut lookups = (0..2 * MESSAGES_PER_STEP)
            .map(|_| Box::pin(mailbox.block(reference)))
            .collect::<Vec<_>>();
        for lookup in &mut lookups {
            assert!(poll!(lookup).is_pending());
        }
        let handle = promoter.start();
        let (answered, waiting) = lookups.split_at_mut(MESSAGES_PER_STEP);
        for lookup in answered {
            assert!(lookup.await.unwrap().is_none());
        }
        // The promotion step starts before the rest, and it never finishes.
        context.sleep(std::time::Duration::from_millis(10)).await;
        for lookup in waiting {
            assert!(poll!(lookup).is_pending());
        }
        handle.abort();
    });
}

#[test]
fn publication_overflow_drops_bodies_and_preserves_install_order() {
    let body = TestBody::new(Sha256::hash(&[b"body parent"]), Height::new(1), 0);
    let header = TransactionBlockHeader::new(
        Epoch::new(1),
        ChainId::new(0),
        Height::new(1),
        Sha256::hash(&[b"producer parent"]),
        body.digest(),
    )
    .unwrap();
    let block = Arc::new(TransactionBlock::<Sha256, _>::new(header, body).unwrap());
    let mut overflow = VecDeque::new();
    Message::handle(
        &mut overflow,
        Message::Published {
            through: OutputIndex::ZERO,
            hot: vec![HotOutput {
                stored: StoredRef {
                    index: OutputIndex::ZERO,
                    reference: block.reference(),
                    encoded_len: u64::try_from(block.encode_size()).unwrap(),
                    floor_generation: 0,
                },
                block,
            }],
        },
    );
    Message::handle(
        &mut overflow,
        Message::Installed {
            floor_generation: 1,
            through: Some(OutputIndex::ZERO),
            frontiers: Vec::new(),
        },
    );
    Message::handle(
        &mut overflow,
        Message::Published {
            through: OutputIndex::new(1),
            hot: Vec::new(),
        },
    );

    assert_eq!(overflow.len(), 3);
    assert!(matches!(
        &overflow[0],
        Message::Published { through, hot }
            if *through == OutputIndex::ZERO && hot.is_empty()
    ));
    assert!(matches!(
        &overflow[1],
        Message::Installed {
            floor_generation: 1,
            ..
        }
    ));
    assert!(matches!(
        &overflow[2],
        Message::Published { through, hot }
            if *through == OutputIndex::new(1) && hot.is_empty()
    ));
}
