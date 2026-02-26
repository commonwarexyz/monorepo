use super::harnesses::*;
use crate::{
    marshal::{mocks::application::Application, Identifier},
    types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
    Heightable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider},
    sha256::Sha256,
    Digestible, Hasher as _,
};
use commonware_p2p::{simulated::Link, Manager};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner};
use commonware_utils::{vec::NonEmptyVec, NZUsize};
use futures::StreamExt;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{collections::BTreeMap, time::Duration};

// =============================================================================
// Generic Test Functions
// =============================================================================

/// Run the finalization test with the given parameters.
pub fn finalize<H: TestHarness>(seed: u64, link: Link, quorum_sees_finalization: bool) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(H::finalize_timeout())),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        let mut manager = oracle.manager();
        manager
            .track(0, participants.clone().try_into().unwrap())
            .await;

        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants, link.clone()).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            parent = H::digest(&block);
            parent_commitment = H::commitment(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        blocks.shuffle(&mut context);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (H::num_validators() as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block).await;

            context.sleep(link.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(height.previous().unwrap().get()),
                H::parent_commitment(block),
                H::commitment(block),
            );
            let notarization = H::make_notarization(proposal.clone(), &schemes, H::quorum());
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, H::quorum());
            if quorum_sees_finalization {
                let do_finalize = context.gen_bool(0.2);
                for (i, h) in handles
                    .iter_mut()
                    .choose_multiple(&mut context, H::num_validators() as usize)
                    .iter_mut()
                    .enumerate()
                {
                    if (do_finalize && i < H::quorum() as usize)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            } else {
                for h in handles.iter_mut() {
                    if context.gen_bool(0.2)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            if applications.len() != H::num_validators() as usize {
                continue;
            }
            finished = true;
            for app in applications.values() {
                if app.blocks().len() != NUM_BLOCKS as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        context.auditor().state()
    })
}

/// Test that marshal can pipeline application acknowledgements up to the configured backlog.
pub fn ack_pipeline_backlog<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xA11CE)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let validator = participants[0].clone();
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let setup = H::setup_validator_with(
            context.with_label("validator_0"),
            &mut oracle,
            validator,
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            application,
        )
        .await;
        let application = setup.application;
        let handles = [ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        }];
        let mut handle = handles[0].clone();

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=5 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                H::num_validators() as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let round = Round::new(
                epocher.containing(H::height(&block)).unwrap().epoch(),
                View::new(i),
            );
            H::verify(&mut handle, round, &block).await;
            let proposal = H::make_proposal(
                round,
                View::new(i.saturating_sub(1)),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        // Backlog should fill to configured capacity before any ack is released.
        while application.blocks().len() < 3 || application.pending_ack_heights().len() < 3 {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            application.pending_ack_heights(),
            vec![Height::new(1), Height::new(2), Height::new(3)]
        );
        assert!(!application.blocks().contains_key(&Height::new(4)));
        assert!(!application.blocks().contains_key(&Height::new(5)));

        // Releasing acks should preserve FIFO order and allow further dispatch.
        for expected in 1..=5 {
            let expected = Height::new(expected);
            while application.pending_ack_heights().first().copied() != Some(expected) {
                context.sleep(Duration::from_millis(10)).await;
            }
            let acknowledged = application
                .acknowledge_next()
                .expect("pending ack should be present");
            assert_eq!(acknowledged, expected);
        }

        // All finalized blocks should eventually be delivered after draining the backlog.
        while application.blocks().len() < 5 || !application.pending_ack_heights().is_empty() {
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

/// Test that batched pending-ack progress survives restart.
pub fn ack_pipeline_backlog_persists_on_restart<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xA11CF)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let validator = participants[0].clone();
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let setup = H::setup_validator_with(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            application,
        )
        .await;
        let application = setup.application;
        let handles = [ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        }];
        let mut handle = handles[0].clone();

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=3 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                H::num_validators() as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let round = Round::new(
                epocher.containing(H::height(&block)).unwrap().epoch(),
                View::new(i),
            );
            H::verify(&mut handle, round, &block).await;
            let proposal = H::make_proposal(
                round,
                View::new(i.saturating_sub(1)),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        while application.pending_ack_heights().len() < 3 {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            application.pending_ack_heights(),
            vec![Height::new(1), Height::new(2), Height::new(3)]
        );

        // Acknowledge all pending blocks without yielding so marshal can drain
        // them in one ack arm and sync metadata once.
        assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
        assert_eq!(application.acknowledge_next(), Some(Height::new(2)));
        assert_eq!(application.acknowledge_next(), Some(Height::new(3)));

        // Yield to marshal.
        context.sleep(Duration::from_millis(10)).await;

        // Assert that the application has processed up to height 3.
        assert_eq!(
            application.tip().map(|(height, _)| height),
            Some(Height::new(3))
        );

        // Restart marshal and confirm the processed height restored from metadata.
        let restart = H::setup_validator_with(
            context.with_label("validator_0_restart"),
            &mut oracle,
            validator,
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            Application::manual_ack(),
        )
        .await;
        assert_eq!(restart.height, Height::new(3));
    });
}

/// Test sync height floor.
pub fn sync_height_floor<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xFF)
            .with_timeout(Some(Duration::from_secs(300))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        let mut manager = oracle.manager();
        manager
            .track(0, participants.clone().try_into().unwrap())
            .await;

        // Skip first validator
        for (i, validator) in participants.iter().enumerate().skip(1) {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants[1..], LINK).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            parent = H::digest(&block);
            parent_commitment = H::commitment(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (applications.len() as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block).await;

            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(height.previous().unwrap().get()),
                H::parent_commitment(block),
                H::commitment(block),
            );
            let notarization = H::make_notarization(proposal.clone(), &schemes, H::quorum());
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, H::quorum());
            for h in handles.iter_mut() {
                H::report_finalization(&mut h.mailbox, fin.clone()).await;
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            for app in applications.values().skip(1) {
                if app.blocks().len() != NUM_BLOCKS as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        // Create the first validator now
        let validator = participants.first().unwrap();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut mailbox = setup.mailbox;

        setup_network_links(&mut oracle, &participants, LINK).await;

        const NEW_SYNC_FLOOR: u64 = 100;
        let second_handle = &mut handles[1];
        let latest_finalization = second_handle
            .mailbox
            .get_finalization(Height::new(NUM_BLOCKS))
            .await
            .unwrap();

        mailbox.set_floor(Height::new(NEW_SYNC_FLOOR)).await;
        H::report_finalization(&mut mailbox, latest_finalization).await;

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            if app.blocks().len() != (NUM_BLOCKS - NEW_SYNC_FLOOR) as usize {
                finished = false;
                continue;
            }
            let Some((height, _)) = app.tip() else {
                finished = false;
                continue;
            };
            if height.get() < NUM_BLOCKS {
                finished = false;
                continue;
            }
        }

        for height in 1..=NUM_BLOCKS {
            let block = mailbox
                .get_block(Identifier::Height(Height::new(height)))
                .await;
            if height <= NEW_SYNC_FLOOR {
                assert!(block.is_none());
            } else {
                assert_eq!(block.unwrap().height().get(), height);
            }
        }
    })
}

/// Test pruning of finalized archives.
pub fn prune_finalized_archives<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new().with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let validator = participants[0].clone();
        let partition_prefix = format!("prune-test-{}", validator.clone());
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        let init_marshal = |ctx: deterministic::Context| {
            let validator = validator.clone();
            let schemes = schemes.clone();
            let partition_prefix = partition_prefix.clone();
            let page_cache = page_cache.clone();
            let oracle = &oracle;
            async move {
                H::setup_prunable_validator(
                    ctx,
                    oracle,
                    validator,
                    &schemes,
                    &partition_prefix,
                    page_cache,
                )
                .await
            }
        };

        let (mut mailbox, extra, application) = init_marshal(context.with_label("init")).await;
        let _ = extra; // Used by CodingHarness, silence warning for StandardHarness

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        for i in 1..=20u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                H::num_validators() as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let bounds = epocher.containing(Height::new(i)).unwrap();
            let round = Round::new(bounds.epoch(), View::new(i));

            let mut handle = ValidatorHandle {
                mailbox: mailbox.clone(),
                extra: extra.clone(),
            };
            H::verify(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut mailbox, finalization).await;
        }

        while application.blocks().len() < 20 {
            context.sleep(Duration::from_millis(10)).await;
        }

        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should exist before pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should exist before pruning"
            );
        }

        mailbox.prune(Height::new(25)).await;
        context.sleep(Duration::from_millis(50)).await;
        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning above floor"
            );
        }

        mailbox.prune(Height::new(10)).await;
        context.sleep(Duration::from_millis(100)).await;
        for i in 1..10u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned"
            );
        }

        for i in 10..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should still exist after pruning"
            );
        }

        mailbox.prune(Height::new(20)).await;
        context.sleep(Duration::from_millis(100)).await;
        for i in 10..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned after second prune"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned after second prune"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist"
        );

        drop(mailbox);
        drop(extra);
        let (mailbox, _extra, _application) = init_marshal(context.with_label("restart")).await;

        for i in 1..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should still be pruned after restart"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should still be pruned after restart"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist after restart"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist after restart"
        );
    })
}

/// Regression test: delayed block backfill delivered after floor advancement must not crash.
///
/// This models a resolver peer that responds to `Request::Block` only after the
/// victim has advanced its floor and pruned finalized storage. The stale delivery
/// must be rejected and must not be persisted.
pub fn reject_stale_block_delivery_after_floor_update<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xBADC0DE)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(1));
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let victim = participants[0].clone();
        let attacker = participants[1].clone();
        let peers = vec![victim.clone(), attacker.clone()];

        let mut manager = oracle.manager();
        manager.track(0, peers.clone().try_into().unwrap()).await;

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let (mut victim_mailbox, victim_extra, _victim_application) = H::setup_prunable_validator(
            context.with_label("victim"),
            &oracle,
            victim.clone(),
            &schemes,
            &format!("stale-floor-victim-{}", victim),
            page_cache.clone(),
        )
        .await;
        let (attacker_mailbox, attacker_extra, _attacker_application) =
            H::setup_prunable_validator(
                context.with_label("attacker"),
                &oracle,
                attacker.clone(),
                &schemes,
                &format!("stale-floor-attacker-{}", attacker),
                page_cache,
            )
            .await;
        let _ = victim_extra; // Used by CodingHarness, silence warning for StandardHarness.

        setup_network_links(&mut oracle, &peers, LINK).await;
        oracle
            .remove_link(attacker.clone(), victim.clone())
            .await
            .unwrap();

        // Make the attacker able to serve the block by commitment.
        let stale_height = Height::new(5);
        let round = Round::new(Epoch::zero(), View::new(stale_height.get()));
        let stale_block = H::make_test_block(
            Sha256::hash(b"stale-parent"),
            H::genesis_parent_commitment(),
            stale_height,
            stale_height.get(),
            H::num_validators() as u16,
        );
        let commitment = H::commitment(&stale_block);
        let mut attacker_handle = ValidatorHandle {
            mailbox: attacker_mailbox,
            extra: attacker_extra,
        };
        H::propose(&mut attacker_handle, round, &stale_block).await;
        H::verify(&mut attacker_handle, round, &stale_block).await;

        // Trigger victim fetch for this block via finalization report.
        let proposal = H::make_proposal(
            round,
            View::new(stale_height.get() - 1),
            H::parent_commitment(&stale_block),
            commitment,
        );
        let finalization = H::make_finalization(proposal, &schemes, H::quorum());
        H::report_finalization(&mut victim_mailbox, finalization).await;

        // Let block requests get issued while responses are still blocked.
        context.sleep(Duration::from_millis(500)).await;

        // Advance floor beyond the stale block and prune.
        let floor = Height::new(10);
        victim_mailbox.set_floor(floor).await;
        // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
        // has been processed before we re-enable the delayed delivery path.
        let _ = victim_mailbox.get_finalization(floor).await;

        // Restore attacker -> victim traffic so delayed resolver responses can arrive.
        oracle
            .add_link(attacker.clone(), victim.clone(), LINK)
            .await
            .unwrap();
        context.sleep(Duration::from_secs(3)).await;

        // Stale-but-valid delivery should not be considered Byzantine behavior.
        let blocked = oracle.blocked().await.unwrap();
        assert!(
            !blocked
                .iter()
                .any(|(blocker, blocked)| blocker == &victim && blocked == &attacker),
            "stale delivery below floor must not block the serving peer"
        );

        assert!(
            victim_mailbox.get_block(stale_height).await.is_none(),
            "stale block below floor must not be persisted"
        );
        assert!(
            victim_mailbox
                .get_finalization(stale_height)
                .await
                .is_none(),
            "stale finalization below floor must not be persisted"
        );
    });
}

/// Test basic block subscription delivery.
pub fn subscribe_basic_block_delivery<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        let subscription_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest)
            .await;

        H::propose(&mut handle, Round::new(Epoch::zero(), View::new(1)), &block).await;
        H::verify(&mut handle, Round::new(Epoch::zero(), View::new(1)), &block).await;

        let proposal = H::make_proposal(
            Round::new(Epoch::zero(), View::new(1)),
            View::zero(),
            H::parent_commitment(&block),
            commitment,
        );
        let notarization = H::make_notarization(proposal.clone(), &schemes, H::quorum());
        H::report_notarization(&mut handle.mailbox, notarization).await;

        let finalization = H::make_finalization(proposal, &schemes, H::quorum());
        H::report_finalization(&mut handle.mailbox, finalization).await;

        let received_block = subscription_rx.await.unwrap();
        assert_eq!(received_block.digest(), digest);
        assert_eq!(received_block.height().get(), 1);
    })
}

/// Test multiple subscriptions.
pub fn subscribe_multiple_subscriptions<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block1 = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(2))), digest2)
            .await;
        let sub3_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;

        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block).await;

            let proposal = H::make_proposal(
                round,
                View::new(view.checked_sub(1).unwrap()),
                H::parent_commitment(block),
                H::commitment(block),
            );
            let notarization = H::make_notarization(proposal.clone(), &schemes, H::quorum());
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received1_sub1 = sub1_rx.await.unwrap();
        let received2 = sub2_rx.await.unwrap();
        let received1_sub3 = sub3_rx.await.unwrap();

        assert_eq!(received1_sub1.digest(), digest1);
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received1_sub3.digest(), digest1);
        assert_eq!(received1_sub1.height().get(), 1);
        assert_eq!(received2.height().get(), 2);
        assert_eq!(received1_sub3.height().get(), 1);
    })
}

/// Test canceled subscriptions.
pub fn subscribe_canceled_subscriptions<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block1 = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(1))), digest1)
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(Some(Round::new(Epoch::zero(), View::new(2))), digest2)
            .await;

        drop(sub1_rx);

        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block).await;

            let proposal = H::make_proposal(
                round,
                View::new(view.checked_sub(1).unwrap()),
                H::parent_commitment(block),
                H::commitment(block),
            );
            let notarization = H::make_notarization(proposal.clone(), &schemes, H::quorum());
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received2.height().get(), 2);
    })
}

/// Test blocks from different sources.
pub fn subscribe_blocks_from_different_sources<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let n = participants.len() as u16;
        let block1 =
            H::make_test_block(parent, H::genesis_parent_commitment(), Height::new(1), 1, n);
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            n,
        );
        let block3 = H::make_test_block(
            H::digest(&block2),
            H::commitment(&block2),
            Height::new(3),
            3,
            n,
        );
        let block4 = H::make_test_block(
            H::digest(&block3),
            H::commitment(&block3),
            Height::new(4),
            4,
            n,
        );
        let block5 = H::make_test_block(
            H::digest(&block4),
            H::commitment(&block4),
            Height::new(5),
            5,
            n,
        );

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block1))
            .await;
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block2))
            .await;
        let sub3_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block3))
            .await;
        let sub4_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block4))
            .await;
        let sub5_rx = handle
            .mailbox
            .subscribe_by_digest(None, H::digest(&block5))
            .await;

        // Block1: Broadcasted by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block1,
        )
        .await;
        context.sleep(Duration::from_millis(20)).await;

        let received1 = sub1_rx.await.unwrap();
        assert_eq!(received1.digest(), H::digest(&block1));
        assert_eq!(received1.height().get(), 1);

        // Block2: Verified by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
        )
        .await;

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), H::digest(&block2));
        assert_eq!(received2.height().get(), 2);

        // Block3: Notarized by the actor
        let proposal3 = H::make_proposal(
            Round::new(Epoch::zero(), View::new(3)),
            View::new(2),
            H::parent_commitment(&block3),
            H::commitment(&block3),
        );
        let notarization3 = H::make_notarization(proposal3.clone(), &schemes, H::quorum());
        H::report_notarization(&mut handle.mailbox, notarization3).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
        )
        .await;

        let received3 = sub3_rx.await.unwrap();
        assert_eq!(received3.digest(), H::digest(&block3));
        assert_eq!(received3.height().get(), 3);

        // Block4: Finalized by the actor
        let finalization4 = H::make_finalization(
            H::make_proposal(
                Round::new(Epoch::zero(), View::new(4)),
                View::new(3),
                H::parent_commitment(&block4),
                H::commitment(&block4),
            ),
            &schemes,
            H::quorum(),
        );
        H::report_finalization(&mut handle.mailbox, finalization4).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
        )
        .await;

        let received4 = sub4_rx.await.unwrap();
        assert_eq!(received4.digest(), H::digest(&block4));
        assert_eq!(received4.height().get(), 4);

        // Block5: Finalized by the actor with notarization
        let proposal5 = H::make_proposal(
            Round::new(Epoch::zero(), View::new(5)),
            View::new(4),
            H::parent_commitment(&block5),
            H::commitment(&block5),
        );
        let notarization5 = H::make_notarization(proposal5.clone(), &schemes, H::quorum());
        H::report_notarization(&mut handle.mailbox, notarization5).await;
        let finalization5 = H::make_finalization(proposal5, &schemes, H::quorum());
        H::report_finalization(&mut handle.mailbox, finalization5).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
        )
        .await;

        let received5 = sub5_rx.await.unwrap();
        assert_eq!(received5.digest(), H::digest(&block5));
        assert_eq!(received5.height().get(), 5);
    })
}

/// Test basic get_info queries for present and missing data.
pub fn get_info_basic_queries_present_and_missing<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no latest
        assert!(handle.mailbox.get_info(Identifier::Latest).await.is_none());

        // Before finalization, specific height returns None
        assert!(handle.mailbox.get_info(Height::new(1)).await.is_none());

        // Create and verify a block, then finalize it
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block).await;
        context.sleep(LINK.latency).await;

        let proposal = H::make_proposal(
            round,
            View::zero(),
            H::parent_commitment(&block),
            commitment,
        );
        let finalization = H::make_finalization(proposal, &schemes, H::quorum());
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Latest should now be the finalized block
        assert_eq!(
            handle.mailbox.get_info(Identifier::Latest).await,
            Some((Height::new(1), digest))
        );

        // Height 1 now present
        assert_eq!(
            handle.mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Commitment should map to its height
        assert_eq!(
            handle.mailbox.get_info(&digest).await,
            Some((Height::new(1), digest))
        );

        // Missing height
        assert!(handle.mailbox.get_info(Height::new(2)).await.is_none());

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_info(&missing).await.is_none());
    })
}

/// Test get_info latest progression with multiple finalizations.
pub fn get_info_latest_progression_multiple_finalizations<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        let mut digests = Vec::new();

        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Latest should always point to most recently finalized
            assert_eq!(
                handle.mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(i), digest))
            );

            parent = digest;
            parent_commitment = commitment;
            digests.push(digest);
        }

        // Verify each height is accessible
        for (i, digest) in digests.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            assert_eq!(
                handle.mailbox.get_info(height).await,
                Some((height, *digest))
            );
        }
    })
}

/// Test get_block by height and latest.
pub fn get_block_by_height_and_latest<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no blocks
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(1)))
            .await
            .is_none());
        assert!(handle.mailbox.get_block(Identifier::Latest).await.is_none());

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        let mut blocks = Vec::new();

        for i in 1..=3u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
            blocks.push((digest, block));
        }

        // Verify each block by height
        for (i, (digest, _block)) in blocks.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            let fetched = handle
                .mailbox
                .get_block(Identifier::Height(height))
                .await
                .unwrap();
            assert_eq!(fetched.digest(), *digest);
            assert_eq!(fetched.height(), height);
        }

        // Latest should be last block
        let latest = handle.mailbox.get_block(Identifier::Latest).await.unwrap();
        assert_eq!(latest.digest(), blocks[2].0);
        assert_eq!(latest.height(), Height::new(3));

        // Missing height
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(10)))
            .await
            .is_none());
    })
}

/// Test get_block by commitment from various sources.
pub fn get_block_by_commitment_from_sources_and_missing<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create and finalize a block
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block).await;
        context.sleep(LINK.latency).await;

        let proposal = H::make_proposal(
            round,
            View::zero(),
            H::parent_commitment(&block),
            commitment,
        );
        let finalization = H::make_finalization(proposal, &schemes, H::quorum());
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Get by commitment
        let fetched = handle.mailbox.get_block(&digest).await.unwrap();
        assert_eq!(fetched.digest(), digest);
        assert_eq!(fetched.height(), Height::new(1));

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_block(&missing).await.is_none());
    })
}

/// Test get_finalization by height.
pub fn get_finalization_by_height<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no finalization
        assert!(handle
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .is_none());

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();

        for i in 1..=3u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal.clone(), &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Verify finalization is retrievable
            let fin = handle
                .mailbox
                .get_finalization(Height::new(i))
                .await
                .unwrap();
            assert_eq!(H::finalization_payload(&fin), commitment);
            assert_eq!(H::finalization_round(&fin).view(), View::new(i));

            parent = digest;
            parent_commitment = commitment;
        }

        // Missing height
        assert!(handle
            .mailbox
            .get_finalization(Height::new(10))
            .await
            .is_none());
    })
}

/// Test hint_finalized triggers fetch.
pub fn hint_finalized_triggers_fetch<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(42)
            .with_timeout(Some(Duration::from_secs(60))),
    );
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), Some(3));
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        // Register the initial peer set
        let mut manager = oracle.manager();
        manager
            .track(0, participants.clone().try_into().unwrap())
            .await;

        // Set up two validators
        let setup0 = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            participants[0].clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app0 = setup0.application;
        let mut handle0 = ValidatorHandle {
            mailbox: setup0.mailbox,
            extra: setup0.extra,
        };

        let setup1 = H::setup_validator(
            context.with_label("validator_1"),
            &mut oracle,
            participants[1].clone(),
            ConstantProvider::new(schemes[1].clone()),
        )
        .await;
        let handle1: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup1.mailbox,
            extra: setup1.extra,
        };

        // Add links between validators
        setup_network_links(&mut oracle, &participants[..2], LINK).await;

        // Validator 0: Create and finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::new(0), View::new(i));

            H::propose(&mut handle0, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle0.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Wait for validator 0 to process all blocks
        while app0.blocks().len() < 5 {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Validator 1 should not have block 5 yet
        assert!(handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none());

        // Validator 1: hint that block 5 is finalized, targeting validator 0
        handle1
            .mailbox
            .hint_finalized(Height::new(5), NonEmptyVec::new(participants[0].clone()))
            .await;

        // Wait for the fetch to complete
        while handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none()
        {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Verify validator 1 now has the finalization
        let finalization = handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .expect("finalization should be fetched");
        assert_eq!(H::finalization_round(&finalization).view(), View::new(5));
    })
}

/// Test ancestry stream.
pub fn ancestry_stream<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let me = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Finalize blocks at heights 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Stream from latest -> height 1
        let (_, commitment) = handle.mailbox.get_info(Identifier::Latest).await.unwrap();
        let ancestry = handle.mailbox.ancestry((None, commitment)).await.unwrap();
        let blocks = ancestry.collect::<Vec<_>>().await;

        // Ensure correct delivery order: 5,4,3,2,1
        assert_eq!(blocks.len(), 5);
        (0..5).for_each(|i| {
            assert_eq!(blocks[i].height().get(), 5 - i as u64);
        });
    })
}

/// Test finalize same height different views.
pub fn finalize_same_height_different_views<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        // Set up two validators
        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate().take(2) {
            let setup = H::setup_validator(
                context.with_label(&format!("validator_{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Both validators receive the block
        for handle in handles.iter_mut() {
            H::propose(handle, Round::new(Epoch::new(0), View::new(1)), &block).await;
        }
        context.sleep(LINK.latency).await;

        // Validator 0: Finalize with view 1
        let proposal_v1 = H::make_proposal(
            Round::new(Epoch::new(0), View::new(1)),
            View::new(0),
            H::parent_commitment(&block),
            commitment,
        );
        let notarization_v1 = H::make_notarization(proposal_v1.clone(), &schemes, H::quorum());
        let finalization_v1 = H::make_finalization(proposal_v1.clone(), &schemes, H::quorum());
        H::report_notarization(&mut handles[0].mailbox, notarization_v1.clone()).await;
        H::report_finalization(&mut handles[0].mailbox, finalization_v1.clone()).await;

        // Validator 1: Finalize with view 2 (simulates receiving finalization from different view)
        let proposal_v2 = H::make_proposal(
            Round::new(Epoch::new(0), View::new(2)),
            View::new(0),
            H::parent_commitment(&block),
            commitment,
        );
        let notarization_v2 = H::make_notarization(proposal_v2.clone(), &schemes, H::quorum());
        let finalization_v2 = H::make_finalization(proposal_v2.clone(), &schemes, H::quorum());
        H::report_notarization(&mut handles[1].mailbox, notarization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v2.clone()).await;

        // Wait for finalization processing
        context.sleep(Duration::from_millis(100)).await;

        // Verify both validators stored the block correctly
        let block0 = handles[0].mailbox.get_block(Height::new(1)).await.unwrap();
        let block1 = handles[1].mailbox.get_block(Height::new(1)).await.unwrap();
        assert_eq!(block0.digest(), digest);
        assert_eq!(block1.digest(), digest);

        // Verify both validators have finalizations stored
        let fin0 = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        let fin1 = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();

        // Verify the finalizations have the expected different views
        assert_eq!(H::finalization_payload(&fin0), commitment);
        assert_eq!(H::finalization_round(&fin0).view(), View::new(1));
        assert_eq!(H::finalization_payload(&fin1), commitment);
        assert_eq!(H::finalization_round(&fin1).view(), View::new(2));

        // Both validators can retrieve block by height
        assert_eq!(
            handles[0].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );
        assert_eq!(
            handles[1].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Test that a validator receiving BOTH finalizations handles it correctly
        H::report_finalization(&mut handles[0].mailbox, finalization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v1.clone()).await;
        context.sleep(Duration::from_millis(100)).await;

        // Validator 0 should still have the original finalization (v1)
        let fin0_after = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(H::finalization_round(&fin0_after).view(), View::new(1));

        // Validator 1 should still have the original finalization (v2)
        let fin1_after = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(H::finalization_round(&fin1_after).view(), View::new(2));
    })
}

/// Test init processed height.
pub fn init_processed_height<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        let validator = participants[0].clone();

        // First session: create validator and finalize some blocks
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };
        let initial_height = setup.height;

        // Initially should be zero (no blocks processed)
        assert_eq!(initial_height, Height::zero());

        // Finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment();
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = H::make_proposal(
                round,
                View::new(i - 1),
                H::parent_commitment(&block),
                commitment,
            );
            let finalization = H::make_finalization(proposal, &schemes, H::quorum());
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Wait for application to process all blocks
        while app.blocks().len() < 5 {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Drop the handle to simulate shutdown
        drop(handle);

        // Second session: create new validator instance, should recover processed height
        let setup2 = H::setup_validator(
            context.with_label("validator_0_restart"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let recovered_height = setup2.height;

        // Should have recovered to height 5
        assert_eq!(recovered_height, Height::new(5));
    })
}

/// Test broadcast caches block.
pub fn broadcast_caches_block<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let mut oracle = setup_network(context.clone(), None);
        let Fixture {
            participants,
            schemes,
            ..
        } = H::fixture(&mut context, NAMESPACE, H::num_validators());

        // Set up one validator
        let validator = participants[0].clone();
        let setup = H::setup_validator(
            context.with_label("validator_0"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment();
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Broadcast the block
        H::propose(&mut handle, Round::new(Epoch::new(0), View::new(1)), &block).await;

        // Ensure the block is cached and retrievable
        handle
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");

        // Restart marshal, removing any in-memory cache
        let setup2 = H::setup_validator(
            context.with_label("validator_0_restart"),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle2: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup2.mailbox,
            extra: setup2.extra,
        };

        // Put a notarization into the cache to re-initialize the ephemeral cache for the
        // first epoch.
        let notarization = H::make_notarization(
            H::make_proposal(
                Round::new(Epoch::new(0), View::new(1)),
                View::new(0),
                H::parent_commitment(&block),
                commitment,
            ),
            &schemes,
            H::quorum(),
        );
        H::report_notarization(&mut handle2.mailbox, notarization).await;

        // Ensure the block is cached and retrievable
        handle2
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");
    })
}
