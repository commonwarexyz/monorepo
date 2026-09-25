use super::{
    App, Block, NoopQmdbResolver, SingleDatabaseSet, build_chain,
    common::{EPOCH_LENGTH, IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, archive_config},
    fixtures, qmdb_config,
};
use crate::stateful::{
    Application, Config, Stateful, SyncPlan,
    db::{DatabaseSet, SyncEngineConfig},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::{self, core::Actor as MarshalActor, resolver::handler, standard::Standard},
    simplex::types::Activity,
    types::{FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{Digestible as _, certificate::ConstantProvider};
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::archive::prunable;
use commonware_utils::{NZU64, NZUsize, channel::ring};
use std::{sync::Arc, time::Duration};

/// Keeps a finalized target unapplied across recovery cuts.
#[derive(Clone)]
struct HoldBlock<R> {
    inner: R,
    height: Height,
    held: ring::Sender<marshal::Update<Block>>,
}

impl<R: Reporter<Activity = marshal::Update<Block>>> Reporter for HoldBlock<R> {
    type Activity = marshal::Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if matches!(&activity, marshal::Update::Block(block, _) if block.height == self.height) {
            assert!(
                self.held.send_lossy(activity),
                "floor observation receiver dropped"
            );
            Feedback::Ok
        } else {
            self.inner.report(activity)
        }
    }
}

#[rstest::rstest]
#[case::within_section(3)]
#[case::section_boundary(4)]
fn live_floor_preserves_application_recovery(#[case] floor_height: u64) {
    let mut checkpoint = None;
    let mut state = None;
    for boot in 0..4 {
        let runner = checkpoint.map_or_else(
            || deterministic::Runner::timed(Duration::from_secs(30)),
            deterministic::Runner::from,
        );
        let (next_state, recovered) = runner.start_and_recover(move |context| async move {
            let (genesis, blocks, fixture) = match state {
                Some(state) => state,
                None => {
                    let (genesis, blocks) = build_chain(&context, floor_height).await;
                    let fixture =
                        fixtures::single_validator(b"_COMMONWARE_GLUE_LIVE_FLOOR_RECOVERY");
                    (genesis, blocks, fixture)
                }
            };
            let floor_height = Height::new(floor_height);
            let predecessor = floor_height.previous().unwrap();
            let predecessor_target = <App as Application<deterministic::Context>>::sync_targets(
                &blocks[predecessor.get() as usize - 1],
            );
            let floor_block = blocks.last().unwrap();
            let floor_target =
                <App as Application<deterministic::Context>>::sync_targets(floor_block);
            assert_ne!(predecessor_target, floor_target);

            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let mut certificates =
                archive_config("floor-marshal", "finalizations", page_cache.clone(), ());
            certificates.items_per_section = NZU64!(4);
            let finalizations_by_height = prunable::Archive::init(
                context.child("finalizations_by_height"),
                certificates,
            )
            .await
            .unwrap();
            let mut archived = archive_config("floor-marshal", "blocks", page_cache.clone(), ());
            archived.items_per_section = NZU64!(4);
            let finalized_blocks =
                prunable::Archive::init(context.child("finalized_blocks"), archived)
                    .await
                    .unwrap();
            let plan = SyncPlan::init(context.child("plan"), "floor-stateful").await;
            if boot > 0 {
                assert!(!plan.should_state_sync(true));
            }
            assert!(plan.floor().is_none());
            let (marshal_actor, mut marshal, floor) =
                MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider: ConstantProvider::new(fixture.schemes[0].clone()),
                        epocher: FixedEpocher::new(EPOCH_LENGTH),
                        start: plan.marshal_start(Arc::new(genesis.clone())),
                        partition_prefix: "floor-marshal".to_string(),
                        mailbox_size: NZUsize!(8),
                        view_retention: ViewDelta::new(10),
                        prunable_items_per_section: NZU64!(4),
                        page_cache: page_cache.clone(),
                        replay_buffer: IO_BUFFER_SIZE,
                        key_write_buffer: IO_BUFFER_SIZE,
                        value_write_buffer: IO_BUFFER_SIZE,
                        block_codec_config: (),
                        max_repair: NZUsize!(4),
                        max_pending_acks: NZUsize!(1),
                        strategy: Sequential,
                    },
                )
                .await;
            let (stateful, mut application) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: App::new(genesis.clone()),
                    db_config: qmdb_config("floor-stateful", page_cache),
                    provider: (),
                    marshal: (marshal.clone(), floor),
                    mailbox_size: NZUsize!(8),
                    plan,
                    resolvers: NoopQmdbResolver,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    prune_config: None,
                },
            );
            let (held, mut floor_reports) = ring::channel(NZUsize!(1));
            let (resolver, _handler) = handler::init(context.child("resolver"), NZUsize!(8));
            let _marshal_actor = marshal_actor.start_unbuffered(
                HoldBlock {
                    inner: application.clone(),
                    height: floor_height,
                    held,
                },
                (resolver, fixtures::IgnoreResolver),
            );
            let _stateful_actor = stateful.start();
            let databases = application.subscribe_databases().await;

            if boot == 0 {
                while marshal.get_processed_height().await != Some(Height::zero()) {}
                for block in &blocks {
                    assert!(marshal.verified(block.context.round, block.clone()).await);
                    marshal.report(Activity::Finalization(fixtures::finalization(
                        &fixture,
                        block.height.get(),
                        block.digest(),
                    )));
                }
            }

            if boot < 3 {
                // The single pending acknowledgement makes delivery at F a durable
                // fence for the predecessor's application state.
                let report = floor_reports.recv().await.expect("floor report missing");
                assert!(matches!(&report, marshal::Update::Block(block, _) if block.height == floor_height));
                assert_eq!(marshal.get_processed_height().await, Some(predecessor));
                assert_eq!(
                    <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::committed_targets(
                        &databases,
                    )
                    .await,
                    predecessor_target,
                );
                if boot == 0 {
                    // Marshal persists the new floor and prunes its archives before
                    // replying to the queued height query. F remains held here.
                    marshal.set_floor(fixtures::finalization(
                        &fixture,
                        floor_height.get(),
                        floor_block.digest(),
                    ));
                    assert_eq!(marshal.get_processed_height().await, Some(predecessor));
                    assert!(marshal.get_block(floor_height).await.is_some());
                }
                if boot == 2 {
                    // The mailbox reports F after the application acknowledges and
                    // Marshal makes its processed height durable.
                    application.report(report);
                    while marshal.get_processed_height().await != Some(floor_height) {}
                }
            }
            if boot >= 2 {
                assert_eq!(marshal.get_processed_height().await, Some(floor_height));
                assert_eq!(
                    <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::committed_targets(
                        &databases,
                    )
                    .await,
                    floor_target,
                );
            }

            // The first two cuts leave F unapplied. The third applies F, and the
            // fourth opens its committed target from durable storage.
            (genesis, blocks, fixture)
        });
        state = Some(next_state);
        checkpoint = Some(recovered);
    }
}
