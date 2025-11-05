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
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of prunable and immutable storage to store blocks and
//! finalizations. Prunable storage is used to store data that is only needed for a short
//! period of time, such as unverified blocks or notarizations. Immutable storage is used to
//! store data that needs to be persisted indefinitely, such as finalized blocks. This allows
//! the actor to keep its storage footprint small while still providing a full history of the
//! chain.
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - No state sync supported. Will attempt to sync every block in the history of the chain.
//! - Stores the entire history of the chain, which requires indefinite amounts of disk space.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

pub mod actor;
pub use actor::Actor;
pub mod cache;
pub mod config;
pub use config::Config;
pub mod finalizer;
pub mod ingress;
pub use ingress::mailbox::Mailbox;
pub mod resolver;

use crate::{simplex::signing_scheme::Scheme, types::Epoch, Block};
use futures::channel::oneshot;
use std::sync::Arc;

/// Supplies the signing scheme the marshal should use for a given epoch.
pub trait SchemeProvider: Clone + Send + Sync + 'static {
    /// The signing scheme to provide.
    type Scheme: Scheme;

    /// Return the signing scheme that corresponds to `epoch`.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>>;
}

/// An update reported to the application, either a new finalized tip or a finalized block.
///
/// Finalized tips are reported as soon as known, whether or not we hold all blocks up to that height.
/// Finalized blocks are reported to the application in monotonically increasing order (no gaps permitted).
#[derive(Debug)]
pub enum Update<B: Block> {
    /// A new finalized tip.
    Tip(u64, B::Commitment),
    /// A new finalized block and a channel to acknowledge the update.
    ///
    /// To ensure all blocks are delivered at least once, marshal waits to mark
    /// a block as delivered until the application explicitly acknowledges the update.
    /// If the sender is dropped before acknowledgement, marshal will exit (assuming
    /// the application is shutting down).
    Block(B, oneshot::Sender<()>),
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
        SchemeProvider,
    };
    use crate::{
        marshal::ingress::mailbox::Identifier,
        simplex::{
            mocks::fixtures::{bls12381_threshold, Fixture},
            signing_scheme::bls12381_threshold,
            types::{Activity, Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{Epoch, Round},
        utils, Block as _, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk,
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
        Digestible, Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        utils::requester,
        Manager,
    };
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use futures::StreamExt;
    use governor::Quota;
    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::BTreeMap,
        marker::PhantomData,
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

    type D = Sha256Digest;
    type B = Block<D>;
    type K = PublicKey;
    type V = MinPk;
    type S = bls12381_threshold::Scheme<K, V>;
    type P = ConstantSchemeProvider;

    #[derive(Clone)]
    struct ConstantSchemeProvider(Arc<S>);
    impl SchemeProvider for ConstantSchemeProvider {
        type Scheme = S;

        fn scheme(&self, _: Epoch) -> Option<Arc<S>> {
            Some(self.0.clone())
        }
    }
    impl From<S> for ConstantSchemeProvider {
        fn from(scheme: S) -> Self {
            Self(Arc::new(scheme))
        }
    }

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 160;
    const BLOCKS_PER_EPOCH: u64 = 20;
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const UNRELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(50),
        success_rate: 0.7,
    };

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K>,
        validator: K,
        scheme_provider: P,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<S, B>,
    ) {
        let config = Config {
            scheme_provider,
            epoch_length: BLOCKS_PER_EPOCH,
            mailbox_size: 100,
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: 10,
            max_repair: 10,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            immutable_items_per_section: NZU64!(10),
            _marker: PhantomData,
        };

        // Create the resolver
        let mut control = oracle.control(validator.clone());
        let backfill = control.register(1).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            manager: oracle.manager(),
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
        let network = control.register(2).await.unwrap();
        broadcast_engine.start(network);

        let (actor, mailbox) = actor::Actor::init(context.clone(), config).await;
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
    ) -> Oracle<K> {
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

    async fn setup_network_links(oracle: &mut Oracle<K>, peers: &[K], link: Link) {
        for p1 in peers.iter() {
            for p2 in peers.iter() {
                if p2 == p1 {
                    continue;
                }
                oracle
                    .add_link(p1.clone(), p2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_good_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, LINK);
            let result2 = finalize(seed, LINK);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_bad_links() {
        for seed in 0..5 {
            let result1 = finalize(seed, UNRELIABLE_LINK);
            let result2 = finalize(seed, UNRELIABLE_LINK);

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    fn finalize(seed: u64, link: Link) -> String {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(300))),
        );
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), Some(3));
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();

            // Register the initial peer set.
            let mut manager = oracle.manager();
            manager.update(0, participants.clone().into()).await;
            for (i, validator) in participants.iter().enumerate() {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    schemes[i].clone().into(),
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
                let round = Round::new(epoch, height);

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.broadcast(block.clone()).await;
                actor.verified(round, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: height.checked_sub(1).unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators
                let fin = make_finalization(proposal, &schemes, QUORUM);
                for actor in actors.iter_mut() {
                    // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                    // Otherwise, finalize randomly.
                    if height == NUM_BLOCKS
                        || utils::is_last_block_in_epoch(BLOCKS_PER_EPOCH, epoch).is_some()
                        || context.gen_bool(0.2)
                    // 20% chance to finalize randomly
                    {
                        actor.report(Activity::Finalization(fin.clone())).await;
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
    fn test_subscribe_basic_block_delivery() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    schemes[i].clone().into(),
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();

            let subscription_rx = actor.subscribe(Some(Round::from((0, 1))), commitment).await;

            actor.verified(Round::from((0, 1)), block.clone()).await;

            let proposal = Proposal {
                round: Round::new(0, 1),
                parent: 0,
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    schemes[i].clone().into(),
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
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::from((0, 2))), commitment2)
                .await;
            let sub3_rx = actor
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;

            actor.verified(Round::from((0, 1)), block1.clone()).await;
            actor.verified(Round::from((0, 2)), block2.clone()).await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(0, view),
                    parent: view.checked_sub(1).unwrap(),
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    schemes[i].clone().into(),
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
                .subscribe(Some(Round::from((0, 1))), commitment1)
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::from((0, 2))), commitment2)
                .await;

            drop(sub1_rx);

            actor.verified(Round::from((0, 1)), block1.clone()).await;
            actor.verified(Round::from((0, 2)), block2.clone()).await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(0, view),
                    parent: view.checked_sub(1).unwrap(),
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let mut actors = Vec::new();
            for (i, validator) in participants.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    validator.clone(),
                    schemes[i].clone().into(),
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
            actor.broadcast(block1.clone()).await;
            context.sleep(Duration::from_millis(20)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), 1);

            // Block2: Verified by the actor
            actor.verified(Round::from((0, 2)), block2.clone()).await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);

            // Block3: Notarized by the actor
            let proposal3 = Proposal {
                round: Round::new(0, 3),
                parent: 2,
                payload: block3.digest(),
            };
            let notarization3 = make_notarization(proposal3.clone(), &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization3)).await;
            actor.verified(Round::from((0, 3)), block3.clone()).await;

            // Block3: delivered
            let received3 = sub3_rx.await.unwrap();
            assert_eq!(received3.digest(), block3.digest());
            assert_eq!(received3.height(), 3);

            // Block4: Finalized by the actor
            let finalization4 = make_finalization(
                Proposal {
                    round: Round::new(0, 4),
                    parent: 3,
                    payload: block4.digest(),
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(finalization4)).await;
            actor.verified(Round::from((0, 4)), block4.clone()).await;

            // Block4: delivered
            let received4 = sub4_rx.await.unwrap();
            assert_eq!(received4.digest(), block4.digest());
            assert_eq!(received4.height(), 4);

            // Block5: Broadcasted by a remote node (different actor)
            let remote_actor = &mut actors[1].clone();
            remote_actor.broadcast(block5.clone()).await;
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
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
            let round = Round::new(0, 1);
            actor.verified(round, block.clone()).await;

            let proposal = Proposal {
                round,
                parent: 0,
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            // Single validator actor
            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
            )
            .await;

            // Initially none
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Build and finalize heights 1..=3
            let parent0 = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent0, 1, 1);
            let d1 = block1.digest();
            actor.verified(Round::new(0, 1), block1.clone()).await;
            let f1 = make_finalization(
                Proposal {
                    round: Round::new(0, 1),
                    parent: 0,
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
            actor.verified(Round::new(0, 2), block2.clone()).await;
            let f2 = make_finalization(
                Proposal {
                    round: Round::new(0, 2),
                    parent: 1,
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
            actor.verified(Round::new(0, 3), block3.clone()).await;
            let f3 = make_finalization(
                Proposal {
                    round: Round::new(0, 3),
                    parent: 2,
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
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
            let round = Round::new(0, 1);
            actor.verified(round, block.clone()).await;
            let proposal = Proposal {
                round,
                parent: 0,
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
            )
            .await;

            // 1) From cache via verified
            let parent = Sha256::hash(b"");
            let ver_block = B::new::<Sha256>(parent, 1, 1);
            let ver_commitment = ver_block.digest();
            let round1 = Round::new(0, 1);
            actor.verified(round1, ver_block.clone()).await;
            let got = actor
                .get_block(&ver_commitment)
                .await
                .expect("missing block from cache");
            assert_eq!(got.digest(), ver_commitment);

            // 2) From finalized archive
            let fin_block = B::new::<Sha256>(ver_commitment, 2, 2);
            let fin_commitment = fin_block.digest();
            let round2 = Round::new(0, 2);
            actor.verified(round2, fin_block.clone()).await;
            let proposal = Proposal {
                round: round2,
                parent: 1,
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
            )
            .await;

            // Before any finalization, get_finalization should be None
            let finalization = actor.get_finalization(1).await;
            assert!(finalization.is_none());

            // Finalize a block at height 1
            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let commitment = block.digest();
            let round = Round::new(0, 1);
            actor.verified(round, block.clone()).await;
            let proposal = Proposal {
                round,
                parent: 0,
                payload: commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Get finalization by height
            let finalization = actor
                .get_finalization(1)
                .await
                .expect("missing finalization by height");
            assert_eq!(finalization.proposal.parent, 0);
            assert_eq!(finalization.proposal.round, Round::new(0, 1));
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
            } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor) = setup_validator(
                context.with_label("validator-0"),
                &mut oracle,
                me,
                schemes[0].clone().into(),
            )
            .await;

            // Finalize blocks at heights 1-5
            let mut parent = Sha256::hash(b"");
            for i in 1..=5 {
                let block = B::new::<Sha256>(parent, i, i);
                let commitment = block.digest();
                let round = Round::new(0, i);
                actor.verified(round, block.clone()).await;
                let proposal = Proposal {
                    round,
                    parent: i - 1,
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
}
