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
//! - [crate::threshold_simplex]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [commonware_broadcast::buffered]: Provides uncertified blocks received from the network
//! - [commonware_resolver::p2p]: Provides a backfill mechanism for missing blocks
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
//! - Only works with [crate::threshold_simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - No state sync supported. Will attempt to sync every block in the history of the chain.
//! - Stores the entire history of the chain, which requires indefinite amounts of disk space.
//! - Uses [`resolver::p2p`](`commonware_resolver::p2p`) for backfilling rather than a general
//!   [`Resolver`](`commonware_resolver::Resolver`).
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

pub mod actor;
pub use actor::Actor;
pub mod config;
pub use config::Config;
pub mod finalizer;
pub use finalizer::Finalizer;
pub mod ingress;
pub use ingress::mailbox::Mailbox;

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        actor,
        config::Config,
        mocks::{application::Application, block::Block},
    };
    use crate::{
        threshold_simplex::types::{
            finalize_namespace, notarize_namespace, seed_namespace, view_message, Activity,
            Finalization, Notarization, Proposal,
        },
        Block as _, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::generate_shares,
            primitives::{
                group::Share,
                ops::{partial_sign_message, threshold_signature_recover},
                poly,
                variant::{MinPk, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::{self, Digest as Sha256Digest},
        Digestible, PrivateKeyExt as _, Signer as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{self, Link, Network, Oracle};
    use commonware_resolver::p2p as resolver;
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use governor::Quota;
    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroUsize},
        time::Duration,
    };

    type D = Sha256Digest;
    type B = Block<D>;
    type P = PublicKey;
    type V = MinPk;
    type Sh = Share;
    type E = PrivateKey;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 100;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<P>,
        coordinator: resolver::mocks::Coordinator<P>,
        secret: E,
        identity: <V as Variant>::Public,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<V, B>,
    ) {
        let config = Config {
            public_key: secret.public_key(),
            identity,
            coordinator,
            mailbox_size: 100,
            backfill_quota: Quota::per_second(NonZeroU32::new(5).unwrap()),
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: 10,
            max_repair: 10,
            codec_config: (),
            partition_prefix: format!("validator-{}", secret.public_key()),
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
        };

        let (actor, mailbox) = actor::Actor::init(context.clone(), config).await;
        let application = Application::<B>::default();

        // Create a buffered broadcast engine and get its mailbox
        let broadcast_config = buffered::Config {
            public_key: secret.public_key(),
            mailbox_size: 100,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = oracle
            .register(secret.public_key(), 1, None, None)
            .await
            .unwrap();
        broadcast_engine.start(network);

        // Start the actor
        let backfill = oracle
            .register(secret.public_key(), 2, None, None)
            .await
            .unwrap();
        actor.start(application.clone(), buffer, backfill);

        (application, mailbox)
    }

    fn make_finalization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Finalization<V, D> {
        let proposal_msg = proposal.encode();

        // Generate proposal signature
        let proposal_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&finalize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let proposal_signature =
            threshold_signature_recover::<V, _>(quorum, &proposal_partials).unwrap();

        // Generate seed signature (for the view number)
        let seed_msg = view_message(proposal.view);
        let seed_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| partial_sign_message::<V>(s, Some(&seed_namespace(NAMESPACE)), &seed_msg))
            .collect();
        let seed_signature = threshold_signature_recover::<V, _>(quorum, &seed_partials).unwrap();

        Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    fn make_notarization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Notarization<V, D> {
        let proposal_msg = proposal.encode();

        // Generate proposal signature
        let proposal_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&notarize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let proposal_signature =
            threshold_signature_recover::<V, _>(quorum, &proposal_partials).unwrap();

        // Generate seed signature (for the view number)
        let seed_msg = view_message(proposal.view);
        let seed_partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| partial_sign_message::<V>(s, Some(&seed_namespace(NAMESPACE)), &seed_msg))
            .collect();
        let seed_signature = threshold_signature_recover::<V, _>(quorum, &seed_partials).unwrap();

        Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    fn setup_network(context: deterministic::Context) -> Oracle<P> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();
        oracle
    }

    fn setup_validators_and_shares(
        context: &mut deterministic::Context,
    ) -> (Vec<E>, Vec<P>, <V as Variant>::Public, Vec<Sh>) {
        let mut schemes = (0..NUM_VALIDATORS)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

        let (identity, shares) = generate_shares::<_, V>(context, None, NUM_VALIDATORS, QUORUM);
        let identity = *poly::public::<V>(&identity);

        (schemes, peers, identity, shares)
    }

    async fn setup_network_links(oracle: &mut Oracle<P>, peers: &[P], link: Link) {
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
        let link = Link {
            latency: Duration::from_millis(100),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let result1 = finalize(seed, link.clone());
            let result2 = finalize(seed, link.clone());

            // Ensure determinism
            assert_eq!(result1, result2);
        }
    }

    #[test_traced("WARN")]
    fn test_finalize_bad_links() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(50),
            success_rate: 0.7,
        };
        for seed in 0..5 {
            let result1 = finalize(seed, link.clone());
            let result2 = finalize(seed, link.clone());

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
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();
            let coordinator = resolver::mocks::Coordinator::new(peers.clone());

            for (i, secret) in schemes.iter().enumerate() {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                applications.insert(peers[i].clone(), application);
                actors.push(actor);
            }

            // Add links between all peers
            setup_network_links(&mut oracle, &peers, link.clone()).await;

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent = sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<sha256::Sha256>(parent, i, i);
                parent = block.digest();
                blocks.push(block);
            }

            // Broadcast and finalize blocks in random order
            blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.broadcast(block.clone()).await;
                actor.verified(height, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    view: height,
                    parent: height.checked_sub(1).unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators
                let fin = make_finalization(proposal, &shares, QUORUM);
                for actor in actors.iter_mut() {
                    // Always finalize the last block. Otherwise, finalize randomly.
                    if height == NUM_BLOCKS || context.gen_bool(0.2) {
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
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = resolver::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            setup_network_links(&mut oracle, &peers, link).await;

            let parent = sha256::hash(b"");
            let block = B::new::<sha256::Sha256>(parent, 1, 1);
            let commitment = block.digest();

            let subscription_rx = actor.subscribe(Some(1), commitment).await;

            actor.verified(1, block.clone()).await;

            let proposal = Proposal {
                view: 1,
                parent: 0,
                payload: commitment,
            };
            let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
            actor.report(Activity::Notarization(notarization)).await;

            let finalization = make_finalization(proposal, &shares, QUORUM);
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
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = resolver::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            setup_network_links(&mut oracle, &peers, link).await;

            let parent = sha256::hash(b"");
            let block1 = B::new::<sha256::Sha256>(parent, 1, 1);
            let block2 = B::new::<sha256::Sha256>(block1.digest(), 2, 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor.subscribe(Some(1), commitment1).await;
            let sub2_rx = actor.subscribe(Some(2), commitment2).await;
            let sub3_rx = actor.subscribe(Some(1), commitment1).await;

            actor.verified(1, block1.clone()).await;
            actor.verified(2, block2.clone()).await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    view,
                    parent: view.checked_sub(1).unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &shares, QUORUM);
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
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = resolver::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            setup_network_links(&mut oracle, &peers, link).await;

            let parent = sha256::hash(b"");
            let block1 = B::new::<sha256::Sha256>(parent, 1, 1);
            let block2 = B::new::<sha256::Sha256>(block1.digest(), 2, 2);
            let commitment1 = block1.digest();
            let commitment2 = block2.digest();

            let sub1_rx = actor.subscribe(Some(1), commitment1).await;
            let sub2_rx = actor.subscribe(Some(2), commitment2).await;

            drop(sub1_rx);

            actor.verified(1, block1.clone()).await;
            actor.verified(2, block2.clone()).await;

            for (view, block) in [(1, block1.clone()), (2, block2.clone())] {
                let proposal = Proposal {
                    view,
                    parent: view.checked_sub(1).unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor.report(Activity::Notarization(notarization)).await;

                let finalization = make_finalization(proposal, &shares, QUORUM);
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
            let mut oracle = setup_network(context.clone());
            let (schemes, peers, identity, shares) = setup_validators_and_shares(&mut context);
            let coordinator = resolver::mocks::Coordinator::new(peers.clone());

            let mut actors = Vec::new();
            for (i, secret) in schemes.iter().enumerate() {
                let (_application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secret.clone(),
                    identity,
                )
                .await;
                actors.push(actor);
            }
            let mut actor = actors[0].clone();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            setup_network_links(&mut oracle, &peers, link).await;

            let parent = sha256::hash(b"");
            let block1 = B::new::<sha256::Sha256>(parent, 1, 1);
            let block2 = B::new::<sha256::Sha256>(block1.digest(), 2, 2);
            let block3 = B::new::<sha256::Sha256>(block2.digest(), 3, 3);
            let block4 = B::new::<sha256::Sha256>(block3.digest(), 4, 4);
            let block5 = B::new::<sha256::Sha256>(block4.digest(), 5, 5);

            let sub1_rx = actor.subscribe(Some(1), block1.digest()).await;
            let sub2_rx = actor.subscribe(Some(2), block2.digest()).await;
            let sub3_rx = actor.subscribe(Some(3), block3.digest()).await;
            let sub4_rx = actor.subscribe(Some(4), block4.digest()).await;
            let sub5_rx = actor.subscribe(Some(5), block5.digest()).await;

            // Block1: Broadcasted by the actor
            actor.broadcast(block1.clone()).await;
            context.sleep(Duration::from_millis(20)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), 1);

            // Block2: Verified by the actor
            actor.verified(2, block2.clone()).await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);

            // Block3: Notarized by the actor
            let proposal3 = Proposal {
                view: 3,
                parent: 2,
                payload: block3.digest(),
            };
            let notarization3 = make_notarization(proposal3.clone(), &shares, QUORUM);
            actor.report(Activity::Notarization(notarization3)).await;
            actor.verified(3, block3.clone()).await;

            // Block3: delivered
            let received3 = sub3_rx.await.unwrap();
            assert_eq!(received3.digest(), block3.digest());
            assert_eq!(received3.height(), 3);

            // Block4: Finalized by the actor
            let finalization4 = make_finalization(
                Proposal {
                    view: 4,
                    parent: 3,
                    payload: block4.digest(),
                },
                &shares,
                QUORUM,
            );
            actor.report(Activity::Finalization(finalization4)).await;
            actor.verified(4, block4.clone()).await;

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
}
