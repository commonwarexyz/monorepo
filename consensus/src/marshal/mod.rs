//! Ordered delivery of finalized blocks.
//!
//! # Architecture
//!
//! The core of the module is the [actor::Actor]. It marshals the finalized blocks into order by:
//!
//! - Receiving uncertified blocks from a broadcast mechanism
//! - Receiving notarizations and finalizations from consensus
//! - Reconstructing a total order of finalized blocks
//! - Providing a backfill mechanism for missing blocks
//!
//! The actor interacts with four main components:
//! - [crate::Reporter]: Receives ordered, finalized blocks at-least-once
//! - [crate::simplex]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [commonware_broadcast::buffered]: Provides uncertified blocks received from the network
//! - [commonware_resolver::Resolver]: Provides a backfill mechanism for missing blocks
//!
//! # Design
//!
//! ## Delivery
//!
//! The actor will deliver a block to the reporter at-least-once. The reporter should be prepared to
//! handle duplicate deliveries. However the blocks will be in order.
//!
//! ## Finalization
//!
//! The actor uses a view-based model to track the state of the chain. Each view corresponds
//! to a potential block in the chain. The actor will only finalize a block (and its ancestors)
//! if it has a corresponding finalization from consensus.
//!
//! _It is possible that there may exist multiple finalizations for the same block in different views. Marshal
//! only concerns itself with verifying a valid finalization exists for a block, not that a specific finalization
//! exists. This means different Marshals may have different finalizations for the same block persisted to disk._
//!
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`], [`store::Blocks`]) storage
//! to store blocks and finalizations. Internal storage is used to store data that is only needed for a short
//! period of time, such as unverified blocks or notarizations. External storage is used to
//! store data that needs to be persisted indefinitely, such as finalized blocks.
//!
//! Marshal will store all blocks after a configurable starting height (or, floor) onward.
//! This allows for state sync from a specific height rather than from genesis. When
//! updating the starting height, marshal will attempt to prune blocks in external storage
//! that are no longer needed.
//!
//! _Setting a configurable starting height will prevent others from backfilling blocks below said height. This
//! feature is only recommended for applications that support state sync (i.e., those that don't require full
//! block history to participate in consensus)._
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

pub mod actor;
pub use actor::Actor;
pub mod cache;
pub mod config;
pub use config::Config;
pub mod ingress;
pub use ingress::mailbox::Mailbox;
pub mod resolver;
pub mod store;

use crate::Block;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};

/// An update reported to the application, either a new finalized tip or a finalized block.
///
/// Finalized tips are reported as soon as known, whether or not we hold all blocks up to that height.
/// Finalized blocks are reported to the application in monotonically increasing order (no gaps permitted).
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A new finalized tip.
    Tip(u64, B::Commitment),
    /// A new finalized block and an [Acknowledgement] for the application to signal once processed.
    ///
    /// To ensure all blocks are delivered at least once, marshal waits to mark a block as delivered
    /// until the application explicitly acknowledges the update. If the [Acknowledgement] is dropped before
    /// handling, marshal will exit (assuming the application is shutting down).
    ///
    /// Because the [Acknowledgement] is clonable, the application can pass [Update] to multiple consumers
    /// (and marshal will only consider the block delivered once all consumers have acknowledged it).
    Block(B, A),
}

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        actor,
        config::Config,
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
    };
    use crate::{
        application::marshaled::Marshaled,
        marshal::ingress::mailbox::{AncestorStream, Identifier},
        simplex::{
            scheme::bls12381_threshold,
            types::{Activity, Context, Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{Epoch, Round, View, ViewDelta},
        utils, Automaton, Block as _, Reporter, VerifyingApplication,
    };
    use commonware_broadcast::buffered;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk,
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
        Committable, Digestible, Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        utils::requester,
        Manager,
    };
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Quota, Runner};
    use commonware_storage::archive::immutable;
    use commonware_utils::{NZUsize, NZU64};
    use futures::StreamExt;
    use rand::{
        seq::{IteratorRandom, SliceRandom},
        Rng,
    };
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroUsize},
        time::{Duration, Instant},
    };
    use tracing::info;

    type D = Sha256Digest;
    type B = Block<D>;
    type K = PublicKey;
    type V = MinPk;
    type S = bls12381_threshold::Scheme<K, V>;
    type P = ConstantProvider<S, Epoch>;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 160;
    const BLOCKS_PER_EPOCH: u64 = 20;
    const LINK: Link = Link {
        latency: Duration::from_millis(100),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const UNRELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(50),
        success_rate: 0.7,
    };
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<S, B>,
    ) {
        let config = Config {
            provider,
            epoch_length: BLOCKS_PER_EPOCH,
            mailbox_size: 100,
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };

        // Create the resolver
        let mut control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            requester_config: requester::Config {
                me: Some(validator.clone()),
                rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(&context, resolver_cfg, backfill);

        // Create a buffered broadcast engine and get its mailbox
        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

        // Initialize finalizations by height
        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_journal_partition: format!(
                    "{}-finalizations-by-height-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: 1024,
                freezer_journal_compression: None,
                freezer_journal_buffer_pool: config.buffer_pool.clone(),
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: NZU64!(10),
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        // Initialize finalized blocks
        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_journal_partition: format!(
                    "{}-finalized_blocks-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: 1024,
                freezer_journal_compression: None,
                freezer_journal_buffer_pool: config.buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: NZU64!(10),
                codec_config: config.block_codec_config,
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let (actor, mailbox) = actor::Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();

        // Start the application
        actor.start(application.clone(), buffer, resolver);

        (application, mailbox)
    }

    fn make_finalization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Finalization<S, D> {
        // Generate proposal signature
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();

        // Generate certificate signatures
        Finalization::from_finalizes(&schemes[0], &finalizes).unwrap()
    }

    fn make_notarization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Notarization<S, D> {
        // Generate proposal signature
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();

        // Generate certificate signatures
        Notarization::from_notarizes(&schemes[0], &notarizes).unwrap()
    }

    fn setup_network(
        context: deterministic::Context,
        tracked_peer_sets: Option<usize>,
    ) -> Oracle<K, deterministic::Context> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets,
            },
        );
        network.start();
        oracle
    }

    async fn setup_network_links(
        oracle: &mut Oracle<K, deterministic::Context>,
        peers: &[K],
        link: Link,
    ) {
        for p1 in peers.iter() {
            for p2 in peers.iter() {
                if p2 == p1 {
                    continue;
                }
                let _ = oracle.add_link(p1.clone(), p2.clone(), link.clone()).await;
            }
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_good_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, LINK, false);
            let result2 = finalize(seed, LINK, false);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_bad_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, UNRELIABLE_LINK, false);
            let result2 = finalize(seed, UNRELIABLE_LINK, false);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let result1 = finalize(seed, LINK, true);
            let result2 = finalize(seed, LINK, true);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("DEBUG")]
    fn test_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let result1 = finalize(seed, UNRELIABLE_LINK, true);
            let result2 = finalize(seed, UNRELIABLE_LINK, true);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    fn finalize(seed: u64, link: Link, quorum_sees_finalization: bool) -> String {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(600))),
        );
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), Some(3));
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();

            // Register the initial peer set.
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;
            for (i, validator) in participants.iter().enumerate() {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push(actor);
            }

            // Add links between all peers
            setup_network_links(&mut oracle, &participants, link.clone()).await;

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent = Sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<Sha256>(parent, i, i);
                parent = block.digest();
                blocks.push(block);
            }

            // Broadcast and finalize blocks in random order
            blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Calculate the epoch and round for the block
                let epoch = utils::epoch(BLOCKS_PER_EPOCH, height);
                let round = Round::new(epoch, View::new(height));

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.proposed(round, block.clone()).await;
                actor.verified(round, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.checked_sub(1).unwrap()),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators
                // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                let fin = make_finalization(proposal, &schemes, QUORUM);
                if quorum_sees_finalization {
                    // If `quorum_sees_finalization` is set, ensure at least `QUORUM` sees a finalization 20%
                    // of the time.
                    let do_finalize = context.gen_bool(0.2);
                    for (i, actor) in actors
                        .iter_mut()
                        .choose_multiple(&mut context, NUM_VALIDATORS as usize)
                        .iter_mut()
                        .enumerate()
                    {
                        if (do_finalize && i < QUORUM as usize)
                            || height == NUM_BLOCKS
                            || utils::is_last_block_in_epoch(BLOCKS_PER_EPOCH, height).is_some()
                        {
                            actor.report(Activity::Finalization(fin.clone())).await;
                        }
                    }
                } else {
                    // If `quorum_sees_finalization` is not set, finalize randomly with a 20% chance for each
                    // individual participant.
                    for actor in actors.iter_mut() {
                        if context.gen_bool(0.2)
                            || height == NUM_BLOCKS
                            || utils::is_last_block_in_epoch(BLOCKS_PER_EPOCH, height).is_some()
                        {
                            actor.report(Activity::Finalization(fin.clone())).await;
                        }
                    }
                }
            }

            // Check that all applications received all blocks.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
                context.sleep(Duration::from_secs(1)).await;

                // If not all validators have finished, try again
                if applications.len() != NUM_VALIDATORS as usize {
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
                    if height < NUM_BLOCKS {
                        finished = false;
                        break;
                    }
                }
            }

            // Return state
            context.auditor().state()
        })
    }

    #[test_traced("WARN")]
    fn test_sync_height_floor() {
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
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();

            // Register the initial peer set.
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;
            for (i, validator) in participants.iter().enumerate().skip(1) {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push(actor);
            }

            // Add links between all peers except for the first, to guarantee
            // the first peer does not receive any blocks during broadcast.
            setup_network_links(&mut oracle, &participants[1..], LINK).await;

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent = Sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<Sha256>(parent, i, i);
                parent = block.digest();
                blocks.push(block);
            }

            // Broadcast and finalize blocks
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Calculate the epoch and round for the block
                let epoch = utils::epoch(BLOCKS_PER_EPOCH, height);
                let round = Round::new(epoch, View::new(height));

                // Broadcast block by one validator
                let actor_index: usize = (height % (applications.len() as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.proposed(round, block.clone()).await;
                actor.verified(round, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(LINK.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.checked_sub(1).unwrap()),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators except for the first.
                let fin = make_finalization(proposal, &schemes, QUORUM);
                for actor in actors.iter_mut() {
                    actor.report(Activity::Finalization(fin.clone())).await;
                }
            }

            // Check that all applications (except for the first) received all blocks.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
                context.sleep(Duration::from_secs(1)).await;

                // If not all validators have finished, try again
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
                    if height < NUM_BLOCKS {
                        finished = false;
                        break;
                    }
                }
            }

            // Create the first validator now that all blocks have been finalized by the others.
            let validator = participants.first().unwrap();
            let (app, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Add links between all peers, including the first.
            setup_network_links(&mut oracle, &participants, LINK).await;

            const NEW_SYNC_FLOOR: u64 = 100;
            let second_actor = &mut actors[1];
            let latest_finalization = second_actor.get_finalization(NUM_BLOCKS).await.unwrap();

            // Set the sync height floor of the first actor to block #100.
            actor.set_floor(NEW_SYNC_FLOOR).await;

            // Notify the first actor of the latest finalization to the first actor to trigger backfill.
            // The sync should only reach the sync height floor.
            actor
                .report(Activity::Finalization(latest_finalization))
                .await;

            // Wait until the first actor has backfilled to the sync height floor.
            let mut finished = false;
            while !finished {
                // Avoid a busy loop
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
                if height < NUM_BLOCKS {
                    finished = false;
                    continue;
                }
            }

            // Check that the first actor has blocks from NEW_SYNC_FLOOR onward, but not before.
            for height in 1..=NUM_BLOCKS {
                let block = actor.get_block(Identifier::Height(height)).await;
                if height <= NEW_SYNC_FLOOR {
                    assert!(block.is_none());
                } else {
                    assert_eq!(block.unwrap().height(), height);
                }
            }
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_basic_block_delivery() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();

            let subscription_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment)
                .await;

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            let proposal = Proposal {
                round: Round::new(Epoch::new(0), View::new(1)),
                parent: View::new(0),
                payload: commitment,
            };
            let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization)).await;

            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            let received_block = subscription_rx.await.unwrap();
            assert_eq!(received_block.digest(), block.digest());
            assert_eq!(received_block.height(), 1);
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_multiple_subscriptions() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent, 1, 1);
            let block2 = B::new::<Sha256>(block1.digest(), 2, 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(2))), commitment2)
                .await;
            let sub3_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let view = View::new(view);
                let proposal = Proposal {
                    round: Round::new(Epoch::zero(), view),
                    parent: view.previous().unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &schemes, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;
            }

            let received1_sub1 = sub1_rx.await.unwrap();
            let received2 = sub2_rx.await.unwrap();
            let received1_sub3 = sub3_rx.await.unwrap();

            assert_eq!(received1_sub1.digest(), block1.digest());
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received1_sub3.digest(), block1.digest());
            assert_eq!(received1_sub1.height(), 1);
            assert_eq!(received2.height(), 2);
            assert_eq!(received1_sub3.height(), 1);
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_canceled_subscriptions() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent, 1, 1);
            let block2 = B::new::<Sha256>(block1.digest(), 2, 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::new(0), View::new(2))), commitment2)
                .await;

            drop(sub1_rx);

            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let view = View::new(view);
                let proposal = Proposal {
                    round: Round::new(Epoch::zero(), view),
                    parent: view.previous().unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &schemes, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;
            }

            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);
        })
    }

    #[test_traced("WARN")]
    fn test_subscribe_blocks_from_different_sources() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent, 1, 1);
            let block2 = B::new::<Sha256>(block1.digest(), 2, 2);
            let block3 = B::new::<Sha256>(block2.digest(), 3, 3);
            let block4 = B::new::<Sha256>(block3.digest(), 4, 4);
            let block5 = B::new::<Sha256>(block4.digest(), 5, 5);

            let sub1_rx = actor.subscribe(None, block1.digest()).await;
            let sub2_rx = actor.subscribe(None, block2.digest()).await;
            let sub3_rx = actor.subscribe(None, block3.digest()).await;
            let sub4_rx = actor.subscribe(None, block4.digest()).await;
            let sub5_rx = actor.subscribe(None, block5.digest()).await;

            // Block1: Broadcasted by the actor
            actor
                .proposed(Round::new(Epoch::zero(), View::new(1)), block1.clone())
                .await;
            context.sleep(Duration::from_millis(20)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), 1);

            // Block2: Verified by the actor
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);

            // Block3: Notarized by the actor
            let proposal3 = Proposal {
                round: Round::new(Epoch::new(0), View::new(3)),
                parent: View::new(2),
                payload: block3.digest(),
            };
            let notarization3 = make_notarization(proposal3.clone(), &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization3)).await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(3)), block3.clone())
                .await;

            // Block3: delivered
            let received3 = sub3_rx.await.unwrap();
            assert_eq!(received3.digest(), block3.digest());
            assert_eq!(received3.height(), 3);

            // Block4: Finalized by the actor
            let finalization4 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::new(0), View::new(4)),
                    parent: View::new(3),
                    payload: block4.digest(),
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(finalization4)).await;
            actor
                .verified(Round::new(Epoch::new(0), View::new(4)), block4.clone())
                .await;

            // Block4: delivered
            let received4 = sub4_rx.await.unwrap();
            assert_eq!(received4.digest(), block4.digest());
            assert_eq!(received4.height(), 4);

            // Block5: Broadcasted by a remote node (different actor)
            let remote_actor = &mut actors[1].clone();
            remote_actor
                .proposed(Round::new(Epoch::zero(), View::new(5)), block5.clone())
                .await;
            context.sleep(Duration::from_millis(20)).await;

            // Block5: delivered
            let received5 = sub5_rx.await.unwrap();
            assert_eq!(received5.digest(), block5.digest());
            assert_eq!(received5.height(), 5);
        })
    }

    #[test_traced("WARN")]
    fn test_get_info_basic_queries_present_and_missing() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Initially, no latest
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Before finalization, specific height returns None
            assert!(actor.get_info(1).await.is_none());

            // Create and verify a block, then finalize it
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let digest = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;

            let proposal = Proposal {
                round,
                parent: View::new(0),
                payload: digest,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Latest should now be the finalized block
            assert_eq!(actor.get_info(Identifier::Latest).await, Some((1, digest)));

            // Height 1 now present
            assert_eq!(actor.get_info(1).await, Some((1, digest)));

            // Commitment should map to its height
            assert_eq!(actor.get_info(&digest).await, Some((1, digest)));

            // Missing height
            assert!(actor.get_info(2).await.is_none());

            // Missing commitment
            let missing = Sha256::hash(b"missing");
            assert!(actor.get_info(&missing).await.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_info_latest_progression_multiple_finalizations() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Initially none
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Build and finalize heights 1..=3
            let parent0 = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent0, 1, 1);
            let d1 = block1.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(1)), block1.clone())
                .await;
            let f1 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::new(0), View::new(1)),
                    parent: View::new(0),
                    payload: d1,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(f1)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((1, d1)));

            let block2 = B::new::<Sha256>(d1, 2, 2);
            let d2 = block2.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(2)), block2.clone())
                .await;
            let f2 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::new(0), View::new(2)),
                    parent: View::new(1),
                    payload: d2,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(f2)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((2, d2)));

            let block3 = B::new::<Sha256>(d2, 3, 3);
            let d3 = block3.digest();
            actor
                .verified(Round::new(Epoch::new(0), View::new(3)), block3.clone())
                .await;
            let f3 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::new(0), View::new(3)),
                    parent: View::new(2),
                    payload: d3,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(f3)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((3, d3)));
        })
    }

    #[test_traced("WARN")]
    fn test_get_block_by_height_and_latest() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Before any finalization, GetBlock::Latest should be None
            let latest_block = actor.get_block(Identifier::Latest).await;
            assert!(latest_block.is_none());
            assert!(application.tip().is_none());

            // Finalize a block at height 1
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;
            let proposal = Proposal {
                round,
                parent: View::new(0),
                payload: commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Get by height
            let by_height = actor.get_block(1).await.expect("missing block by height");
            assert_eq!(by_height.height(), 1);
            assert_eq!(by_height.digest(), commitment);
            assert_eq!(application.tip(), Some((1, commitment)));

            // Get by latest
            let by_latest = actor
                .get_block(Identifier::Latest)
                .await
                .expect("missing block by latest");
            assert_eq!(by_latest.height(), 1);
            assert_eq!(by_latest.digest(), commitment);

            // Missing height
            let by_height = actor.get_block(2).await;
            assert!(by_height.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_block_by_commitment_from_sources_and_missing() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // 1) From cache via verified
            let parent = Sha256::hash(b"");
            let ver_block = B::new::<Sha256>(parent, 1, 1);
            let ver_commitment = ver_block.digest();
            let round1 = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round1, ver_block.clone()).await;
            let got = actor
                .get_block(&ver_commitment)
                .await
                .expect("missing block from cache");
            assert_eq!(got.digest(), ver_commitment);

            // 2) From finalized archive
            let fin_block = B::new::<Sha256>(ver_commitment, 2, 2);
            let fin_commitment = fin_block.digest();
            let round2 = Round::new(Epoch::new(0), View::new(2));
            actor.verified(round2, fin_block.clone()).await;
            let proposal = Proposal {
                round: round2,
                parent: View::new(1),
                payload: fin_commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;
            let got = actor
                .get_block(&fin_commitment)
                .await
                .expect("missing block from finalized archive");
            assert_eq!(got.digest(), fin_commitment);
            assert_eq!(got.height(), 2);

            // 3) Missing commitment
            let missing = Sha256::hash(b"definitely-missing");
            let missing_block = actor.get_block(&missing).await;
            assert!(missing_block.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_get_finalization_by_height() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Before any finalization, get_finalization should be None
            let finalization = actor.get_finalization(1).await;
            assert!(finalization.is_none());

            // Finalize a block at height 1
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();
            let round = Round::new(Epoch::new(0), View::new(1));
            actor.verified(round, block.clone()).await;
            let proposal = Proposal {
                round,
                parent: View::new(0),
                payload: commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Get finalization by height
            let finalization = actor
                .get_finalization(1)
                .await
                .expect("missing finalization by height");
            assert_eq!(finalization.proposal.parent, View::new(0));
            assert_eq!(
                finalization.proposal.round,
                Round::new(Epoch::new(0), View::new(1))
            );
            assert_eq!(finalization.proposal.payload, commitment);

            assert!(actor.get_finalization(2).await.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_ancestry_stream() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Finalize blocks at heights 1-5
            let mut parent = Sha256::hash(b"");
            for i in 1..=5 {
                let block = B::new::<Sha256>(parent, i, i);
                let commitment = block.digest();
                let round = Round::new(Epoch::new(0), View::new(i));
                actor.verified(round, block.clone()).await;
                let proposal = Proposal {
                    round,
                    parent: View::new(i - 1),
                    payload: commitment,
                };
                let finalization = make_finalization(proposal, &schemes, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;

                parent = block.digest();
            }

            // Stream from latest -> height 1
            let (_, commitment) = actor.get_info(Identifier::Latest).await.unwrap();
            let ancestry = actor.ancestry((None, commitment)).await.unwrap();
            let blocks = ancestry.collect::<Vec<_>>().await;

            // Ensure correct delivery order: 5,4,3,2,1
            assert_eq!(blocks.len(), 5);
            (0..5).for_each(|i| {
                assert_eq!(blocks[i].height(), 5 - i as u64);
            });
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: B,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = B;
            type Context = Context<D, K>;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
            ) -> bool {
                // Ancestry verification occurs entirely in `Marshaled`.
                true
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_base_app, marshal) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Create genesis block
            let genesis = B::new::<Sha256>(Sha256::hash(b""), 0, 0);

            // Wrap with Marshaled verifier
            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let mut marshaled =
                Marshaled::new(context.clone(), mock_app, marshal.clone(), BLOCKS_PER_EPOCH);

            // Test case 1: Non-contiguous height
            //
            // We need both blocks in the same epoch.
            // With BLOCKS_PER_EPOCH=20: epoch 0 is heights 0-19, epoch 1 is heights 20-39
            //
            // Store honest parent at height 21 (epoch 1)
            let honest_parent = B::new::<Sha256>(genesis.commitment(), BLOCKS_PER_EPOCH + 1, 1000);
            let parent_commitment = honest_parent.commitment();
            let parent_round = Round::new(Epoch::new(1), View::new(21));
            marshal
                .clone()
                .verified(parent_round, honest_parent.clone())
                .await;

            // Byzantine proposer broadcasts malicious block at height 35
            // In reality this would come via buffered broadcast, but for test simplicity
            // we call broadcast() directly which makes it available for subscription
            let malicious_block = B::new::<Sha256>(parent_commitment, BLOCKS_PER_EPOCH + 15, 2000);
            let malicious_commitment = malicious_block.commitment();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(35)),
                    malicious_block.clone(),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 35
            let byzantine_context = Context {
                round: Round::new(Epoch::new(1), View::new(35)),
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let verify = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent commitment
            //
            // Create another malicious block with correct height but invalid parent commitment
            let malicious_block =
                B::new::<Sha256>(genesis.commitment(), BLOCKS_PER_EPOCH + 2, 3000);
            let malicious_commitment = malicious_block.commitment();
            marshal
                .clone()
                .proposed(
                    Round::new(Epoch::new(1), View::new(22)),
                    malicious_block.clone(),
                )
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 22
            let byzantine_context = Context {
                round: Round::new(Epoch::new(1), View::new(22)),
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() should reject the malicious block
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 3. Validate parent commitment matches (fail)
            // 4. Return false
            let verify = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            assert!(
                !verify.await.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_finalize_same_height_different_views() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Set up two validators
            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate().take(2) {
                let (_app, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
            }

            // Create block at height 1
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();

            // Both validators verify the block
            actors[0]
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;
            actors[1]
                .verified(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            // Validator 0: Finalize with view 1
            let proposal_v1 = Proposal {
                round: Round::new(Epoch::new(0), View::new(1)),
                parent: View::new(0),
                payload: commitment,
            };
            let notarization_v1 = make_notarization(proposal_v1.clone(), &schemes, QUORUM);
            let finalization_v1 = make_finalization(proposal_v1.clone(), &schemes, QUORUM);
            actors[0]
                .report(Activity::Notarization(notarization_v1.clone()))
                .await;
            actors[0]
                .report(Activity::Finalization(finalization_v1.clone()))
                .await;

            // Validator 1: Finalize with view 2 (simulates receiving finalization from different view)
            // This could happen during epoch transitions where the same block gets finalized
            // with different views by different validators.
            let proposal_v2 = Proposal {
                round: Round::new(Epoch::new(0), View::new(2)), // Different view
                parent: View::new(0),
                payload: commitment, // Same block
            };
            let notarization_v2 = make_notarization(proposal_v2.clone(), &schemes, QUORUM);
            let finalization_v2 = make_finalization(proposal_v2.clone(), &schemes, QUORUM);
            actors[1]
                .report(Activity::Notarization(notarization_v2.clone()))
                .await;
            actors[1]
                .report(Activity::Finalization(finalization_v2.clone()))
                .await;

            // Wait for finalization processing
            context.sleep(Duration::from_millis(100)).await;

            // Verify both validators stored the block correctly
            let block0 = actors[0].get_block(1).await.unwrap();
            let block1 = actors[1].get_block(1).await.unwrap();
            assert_eq!(block0, block);
            assert_eq!(block1, block);

            // Verify both validators have finalizations stored
            let fin0 = actors[0].get_finalization(1).await.unwrap();
            let fin1 = actors[1].get_finalization(1).await.unwrap();

            // Verify the finalizations have the expected different views
            assert_eq!(fin0.proposal.payload, block.commitment());
            assert_eq!(fin0.round().view(), View::new(1));
            assert_eq!(fin1.proposal.payload, block.commitment());
            assert_eq!(fin1.round().view(), View::new(2));

            // Both validators can retrieve block by height
            assert_eq!(actors[0].get_info(1).await, Some((1, commitment)));
            assert_eq!(actors[1].get_info(1).await, Some((1, commitment)));

            // Test that a validator receiving BOTH finalizations handles it correctly
            // (the second one should be ignored since archive ignores duplicates for same height)
            actors[0]
                .report(Activity::Finalization(finalization_v2.clone()))
                .await;
            actors[1]
                .report(Activity::Finalization(finalization_v1.clone()))
                .await;
            context.sleep(Duration::from_millis(100)).await;

            // Validator 0 should still have the original finalization (v1)
            let fin0_after = actors[0].get_finalization(1).await.unwrap();
            assert_eq!(fin0_after.round().view(), View::new(1));

            // Validator 1 should still have the original finalization (v2)
            let fin0_after = actors[1].get_finalization(1).await.unwrap();
            assert_eq!(fin0_after.round().view(), View::new(2));
        })
    }

    #[test_traced("INFO")]
    fn test_broadcast_caches_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Set up one validator
            let (i, validator) = participants.iter().enumerate().next().unwrap();
            let mut actor = setup_validator(
                context.with_label(&format!("validator-{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await
            .1;

            // Create block at height 1
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();

            // Broadcast the block
            actor
                .proposed(Round::new(Epoch::new(0), View::new(1)), block.clone())
                .await;

            // Ensure the block is cached and retrievable; This should hit the in-memory cache
            // via `buffered::Mailbox`.
            actor
                .get_block(&commitment)
                .await
                .expect("block should be cached after broadcast");

            // Restart marshal, removing any in-memory cache
            let mut actor = setup_validator(
                context.with_label(&format!("validator-{i}")),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await
            .1;

            // Put a notarization into the cache to re-initialize the ephemeral cache for the
            // first epoch. Without this, the marshal cannot determine the epoch of the block being fetched,
            // so it won't look to restore the cache for the epoch.
            let notarization = make_notarization(
                Proposal {
                    round: Round::new(Epoch::new(0), View::new(1)),
                    parent: View::new(0),
                    payload: commitment,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Notarization(notarization)).await;

            // Ensure the block is cached and retrievable
            let fetched = actor
                .get_block(&commitment)
                .await
                .expect("block should be cached after broadcast");
            assert_eq!(fetched, block);
        });
    }
}
