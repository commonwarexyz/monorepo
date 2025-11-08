//! Ordered delivery of erasure-coded blocks.
//!
//! # Overview
//!
//! The coding marshal couples the consensus pipeline with erasure-coded block broadcast.
//! Blocks are produced by an application, encoded into [`types::Shard`]s, fanned out to peers, and
//! later reconstructed when a notarization or finalization proves that the data is needed.
//! Compared to [`super::standard`], this variant makes more efficient usage of the network's bandwidth
//! by spreading the load of block dissemination across all participants.
//!
//! # Components
//!
//! - [`Actor`]: drives the state machine that orders finalized blocks, handles acknowledgements
//!   from the application, and requests repairs when gaps are detected.
//! - [`shards::Engine`]: broadcasts shards, verifies locally held fragments, and reconstructs
//!   entire [`types::CodedBlock`]s on demand.
//! - [`Mailbox`]: accepts requests coming from other local subsystems and forwards them to the
//!   actor without requiring direct handles.
//! - [`crate::marshal::resolver`]: issues outbound fetches to remote peers when marshal is missing a block,
//!   notarization, or finalization referenced by consensus.
//! - Cache: keeps per-epoch prunable archives of notarized blocks and certificates so the
//!   actor can roll forward quickly without retaining the entire chain in hot storage.
//! - [`types`]: defines commitments, distribution shards, and helper builders used across the
//!   module.
//! - [`Marshaled`]: wraps an [`crate::Application`] implementation so it automatically enforces
//!   epoch boundaries and performs erasure encoding before a proposal leaves the application.
//!
//! # Data Flow
//!
//! 1. The application produces a block through [`Marshaled`], which encodes the payload and
//!    obtains a [`crate::types::CodingCommitment`] describing the shard layout.
//! 2. The block is broadcast via [`shards::Engine`]; each participant receives exactly one shard
//!    and reshares it to everyone else once it verifies the fragment.
//! 3. The [`Actor`] ingests notarizations/finalizations from `simplex`, pulls reconstructed blocks
//!    from the shard engine or backfills them through [`crate::marshal::resolver`], and durably persists the
//!    ordered data.
//! 4. The actor reports finalized blocks to the node’s [`crate::Reporter`] at-least-once and
//!    drives repair loops whenever notarizations reference yet-to-be-delivered payloads.
//!
//! # Storage and Repair
//!
//! Notarized data and certificates live in prunable archives managed by the cache manager, while
//! finalized blocks are migrated into immutable archives. Any gaps are filled by asking peers for
//! specific commitments through the resolver pipeline (`ingress::handler` implements the bridge to
//! [`commonware_resolver`]). The shard engine keeps only ephemeral, in-memory caches; once a block
//! is finalized it is evicted from the reconstruction map, reducing memory pressure.
//!
//! # When to Use
//!
//! Choose this module when the consensus deployment wants erasure-coded dissemination with the
//! same ordering guarantees provided by [`super::standard`]. The API mirrors the standard marshal,
//! so applications can switch between the two by swapping the mailbox pair they hand to
//! [`Marshaled`] and the consensus automaton.

pub mod shards;
pub mod types;

pub(crate) mod cache;

mod mailbox;
pub use mailbox::Mailbox;

mod actor;
pub use actor::Actor;

mod marshaled;
pub use marshaled::Marshaled;

#[cfg(test)]
mod tests {
    use super::actor;
    use crate::{
        marshal::{
            coding::{
                self, shards,
                types::{coding_config_for_participants, CodedBlock, DigestOrCommitment, Shard},
            },
            config::Config,
            mocks::{application::Application, block::Block},
            resolver::p2p as resolver,
            Identifier,
        },
        simplex::{
            scheme::bls12381_threshold,
            types::{Activity, Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{CodingCommitment, Epoch, Epocher, FixedEpocher, Round, View, ViewDelta},
        Block as _, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_coding::{CodecConfig, ReedSolomon};
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
        Manager,
    };
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Quota, Runner};
    use commonware_storage::archive::immutable;
    use commonware_utils::{vec::NonEmptyVec, NZUsize, NZU64};
    use futures::StreamExt;
    use rand::{
        seq::{IteratorRandom, SliceRandom},
        Rng,
    };
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        time::{Duration, Instant},
    };
    use tracing::info;

    type H = Sha256;
    type D = Sha256Digest;
    type B = Block<D>;
    type K = PublicKey;
    type V = MinPk;
    type S = bls12381_threshold::Scheme<K, V>;
    type P = ConstantProvider<S, Epoch>;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const CONCURRENCY: usize = 1;
    const NAMESPACE: &[u8] = b"test";
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 160;
    const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(20);
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
        coding::Mailbox<S, B, ReedSolomon<H>>,
        coding::shards::Mailbox<B, S, ReedSolomon<H>, K>,
        u64,
    ) {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            concurrency: CONCURRENCY,
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
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
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
            codec_config: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::<_, _, Shard<ReedSolomon<Sha256>, Sha256>>::new(
                context.clone(),
                broadcast_config,
            );

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

        let (shard_engine, shard_mailbox) = shards::Engine::new(
            context.clone(),
            buffer,
            (),
            config.mailbox_size,
            CONCURRENCY,
        );
        shard_engine.start();

        let (actor, mailbox, processed_height) = actor::Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();

        // Start the application
        actor.start(application.clone(), shard_mailbox.clone(), resolver);

        (application, mailbox, shard_mailbox, processed_height)
    }

    fn make_finalization(
        proposal: Proposal<CodingCommitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, CodingCommitment> {
        // Generate proposal signature
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();

        // Generate certificate signatures
        Finalization::from_finalizes(&schemes[0], &finalizes).unwrap()
    }

    fn make_notarization(
        proposal: Proposal<CodingCommitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, CodingCommitment> {
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

    #[test_traced("WARN")]
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
                .with_timeout(Some(Duration::from_secs(900))),
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
                let (application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push((actor, shards));
            }

            // Add links between all peers
            setup_network_links(&mut oracle, &participants, link.clone()).await;

            let coding_config = coding_config_for_participants(participants.len() as u16);

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::with_capacity(NUM_BLOCKS as usize);
            let mut parent = Sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<Sha256>(parent, i, i);
                parent = block.digest();
                let coded_block = CodedBlock::new(block, coding_config, CONCURRENCY);
                blocks.push(coded_block);
            }

            // Broadcast and finalize blocks in random order
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height));

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let (mut marshal, mut shards) = actors[actor_index].clone();
                shards.proposed(block.clone(), participants.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the shards before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.checked_sub(1).unwrap()),
                    payload: block.commitment(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                marshal
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Ask each peer to validate their received shards. This will inform them to broadcast
                // their shards to each other.
                for (i, (_, shards)) in actors.iter_mut().enumerate() {
                    let _recv = shards.subscribe_shard_validity(block.commitment(), i).await;
                }

                // Give peers enough time to broadcast their received shards to each other.
                context.sleep(link.latency).await;

                // Finalize block by all validators
                // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                let fin = make_finalization(proposal, &schemes, QUORUM);
                if quorum_sees_finalization {
                    // If `quorum_sees_finalization` is set, ensure at least `QUORUM` sees a finalization 20%
                    // of the time.
                    let do_finalize = context.gen_bool(0.2);
                    for (i, (actor, _)) in actors
                        .iter_mut()
                        .choose_multiple(&mut context, NUM_VALIDATORS as usize)
                        .iter_mut()
                        .enumerate()
                    {
                        // Always finalize 1) the last block in each epoch 2) the last block in the chain.
                        // Otherwise, finalize randomly.
                        // 20% chance to finalize randomly
                        if (do_finalize && i < QUORUM as usize)
                            || height == NUM_BLOCKS
                            || height == bounds.last()
                        {
                            actor.report(Activity::Finalization(fin.clone())).await;
                        }
                    }
                } else {
                    // If `quorum_sees_finalization` is not set, finalize randomly with a 20% chance for each
                    // individual participant.
                    for (actor, _) in actors.iter_mut() {
                        if context.gen_bool(0.2) || height == NUM_BLOCKS || height == bounds.last()
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
                let (application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                applications.insert(validator.clone(), application);
                actors.push((actor, shards));
            }

            // Add links between all peers except for the first, to guarantee
            // the first peer does not receive any blocks during broadcast.
            setup_network_links(&mut oracle, &participants[1..], LINK).await;

            let coding_config = coding_config_for_participants(participants.len() as u16);

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::with_capacity(NUM_BLOCKS as usize);
            let mut parent = Sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<Sha256>(parent, i, i);
                parent = block.digest();
                let coded_block = CodedBlock::new(block, coding_config, CONCURRENCY);
                blocks.push(coded_block);
            }

            // Broadcast and finalize blocks
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height));

                // Broadcast block by one validator
                let actor_index: usize = (height % (applications.len() as u64)) as usize;
                let (mut marshal, mut shards) = actors[actor_index].clone();
                shards.proposed(block.clone(), participants.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the shards before continuing.
                context.sleep(LINK.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.checked_sub(1).unwrap()),
                    payload: block.commitment(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                marshal
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Ask each peer to validate their received shards. This will inform them to broadcast
                // their shards to each other.
                for (i, (_, shards)) in actors.iter_mut().enumerate() {
                    let _recv = shards.subscribe_shard_validity(block.commitment(), i).await;
                }

                // Give peers enough time to broadcast their received shards to each other.
                context.sleep(LINK.latency).await;

                // Finalize block by all validators except for the first.
                let fin = make_finalization(proposal, &schemes, QUORUM);
                for (actor, _) in actors.iter_mut() {
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
            let (app, mut actor, _, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Add links between all peers, including the first.
            setup_network_links(&mut oracle, &participants, LINK).await;

            const NEW_SYNC_FLOOR: u64 = 100;
            let (second_actor, _) = &mut actors[1];
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
                let (_application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push((actor, shards));
            }
            let (mut actor, mut shards) = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let parent = Sha256::hash(b"");
            let block = B::new::<Sha256>(parent, 1, 1);
            let coded_block = CodedBlock::new(
                block.clone(),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                CONCURRENCY,
            );
            let digest = block.digest();

            let subscription_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(1))),
                    DigestOrCommitment::Digest(digest),
                )
                .await;

            shards
                .proposed(coded_block.clone(), participants.clone())
                .await;

            let proposal = Proposal {
                round: Round::new(Epoch::zero(), View::new(1)),
                parent: View::zero(),
                payload: coded_block.commitment(),
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
                let (_application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push((actor, shards));
            }
            let (mut actor, mut shards) = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let parent = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent, 1, 1);
            let coded_block1 = CodedBlock::new(block1.clone(), coding_config, CONCURRENCY);
            let block2 = B::new::<Sha256>(block1.digest(), 2, 2);
            let coded_block2 = CodedBlock::new(block2.clone(), coding_config, CONCURRENCY);
            let digest1 = block1.digest();
            let digest2 = block2.digest();

            let sub1_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(1))),
                    DigestOrCommitment::Digest(digest1),
                )
                .await;
            let sub2_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(2))),
                    DigestOrCommitment::Digest(digest2),
                )
                .await;
            let sub3_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(1))),
                    DigestOrCommitment::Digest(digest1),
                )
                .await;

            shards
                .proposed(coded_block1.clone(), participants.clone())
                .await;
            shards
                .proposed(coded_block2.clone(), participants.clone())
                .await;

            for (view, block) in [(1, coded_block1.clone()), (2, coded_block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(Epoch::zero(), View::new(view)),
                    parent: View::new(view.checked_sub(1).unwrap()),
                    payload: block.commitment(),
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
                let (_application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push((actor, shards));
            }
            let (mut actor, mut shards) = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let parent = Sha256::hash(b"");
            let block1 = B::new::<Sha256>(parent, 1, 1);
            let coded_block1 = CodedBlock::new(block1.clone(), coding_config, CONCURRENCY);
            let block2 = B::new::<Sha256>(block1.digest(), 2, 2);
            let coded_block2 = CodedBlock::new(block2.clone(), coding_config, CONCURRENCY);
            let digest1 = block1.digest();
            let digest2 = block2.digest();

            let sub1_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(1))),
                    DigestOrCommitment::Digest(digest1),
                )
                .await;
            let sub2_rx = actor
                .subscribe(
                    Some(Round::new(Epoch::zero(), View::new(2))),
                    DigestOrCommitment::Digest(digest2),
                )
                .await;

            drop(sub1_rx);

            shards
                .proposed(coded_block1.clone(), participants.clone())
                .await;
            shards
                .proposed(coded_block2.clone(), participants.clone())
                .await;

            for (view, block) in [(1, coded_block1.clone()), (2, coded_block2.clone())] {
                let proposal = Proposal {
                    round: Round::new(Epoch::zero(), View::new(view)),
                    parent: View::new(view.checked_sub(1).unwrap()),
                    payload: block.commitment(),
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
                let (_application, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push((actor, shards));
            }
            let (mut actor, mut shards) = actors[0].clone();

            setup_network_links(&mut oracle, &participants, LINK).await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let parent = Sha256::hash(b"");
            let block1 =
                CodedBlock::new(B::new::<Sha256>(parent, 1, 1), coding_config, CONCURRENCY);
            let block2 = CodedBlock::new(
                B::new::<Sha256>(block1.digest(), 2, 2),
                coding_config,
                CONCURRENCY,
            );
            let block3 = CodedBlock::new(
                B::new::<Sha256>(block2.digest(), 3, 3),
                coding_config,
                CONCURRENCY,
            );

            let sub1_rx = actor
                .subscribe(None, DigestOrCommitment::Digest(block1.digest()))
                .await;
            let sub2_rx = actor
                .subscribe(None, DigestOrCommitment::Digest(block2.digest()))
                .await;
            let sub3_rx = actor
                .subscribe(None, DigestOrCommitment::Digest(block3.digest()))
                .await;

            // Block1: Broadcasted and notarized by the actor
            shards.proposed(block1.clone(), participants.clone()).await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block1.commitment(), i)
                    .await;
            }
            context.sleep(LINK.latency * 2).await;

            let proposal1 = Proposal {
                round: Round::new(Epoch::zero(), View::new(1)),
                parent: View::zero(),
                payload: block1.commitment(),
            };
            let notarization1 = make_notarization(proposal1.clone(), &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization1)).await;

            // Block1: delivered
            let received1 = sub1_rx.await.unwrap();
            assert_eq!(received1.digest(), block1.digest());
            assert_eq!(received1.height(), 1);

            // Block2: Broadcasted and finalized by the actor
            shards.proposed(block2.clone(), participants.clone()).await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block2.commitment(), i)
                    .await;
            }
            context.sleep(LINK.latency * 2).await;

            let proposal2 = Proposal {
                round: Round::new(Epoch::zero(), View::new(2)),
                parent: View::new(1),
                payload: block2.commitment(),
            };
            let finalization2 = make_finalization(proposal2.clone(), &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization2)).await;

            // Block2: delivered
            let received2 = sub2_rx.await.unwrap();
            assert_eq!(received2.digest(), block2.digest());
            assert_eq!(received2.height(), 2);

            // Block3: Broadcasted by a remote actor
            let (_, mut remote_shards) = actors[1].clone();
            remote_shards
                .proposed(block3.clone(), participants.clone())
                .await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block3.commitment(), i)
                    .await;
            }
            context.sleep(LINK.latency * 2).await;

            let proposal3 = Proposal {
                round: Round::new(Epoch::zero(), View::new(3)),
                parent: View::new(2),
                payload: block3.commitment(),
            };
            let notarization3 = make_notarization(proposal3.clone(), &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization3)).await;

            // Block3: delivered
            let received3 = sub3_rx.await.unwrap();
            assert_eq!(received3.digest(), block3.digest());
            assert_eq!(received3.height(), 3);
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
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
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
            let block = CodedBlock::new(
                B::new::<Sha256>(parent, 1, 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                CONCURRENCY,
            );
            let commitment = block.commitment();
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            shards.proposed(block.clone(), participants.clone()).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::zero(),
                payload: commitment,
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
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            // Initially none
            assert!(actor.get_info(Identifier::Latest).await.is_none());

            // Build and finalize heights 1..=3
            let parent0 = Sha256::hash(b"");
            let block1 =
                CodedBlock::new(B::new::<Sha256>(parent0, 1, 1), coding_config, CONCURRENCY);
            let c1 = block1.commitment();
            let d1 = block1.digest();

            shards.proposed(block1, participants.clone()).await;
            context.sleep(LINK.latency).await;

            let f1 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::zero(), View::new(1)),
                    parent: View::zero(),
                    payload: c1,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(f1)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((1, d1)));

            let block2 = CodedBlock::new(B::new::<Sha256>(d1, 2, 2), coding_config, CONCURRENCY);
            let c2 = block2.commitment();
            let d2 = block2.digest();

            shards.proposed(block2, participants.clone()).await;

            let f2 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::zero(), View::new(2)),
                    parent: View::new(1),
                    payload: c2,
                },
                &schemes,
                QUORUM,
            );
            actor.report(Activity::Finalization(f2)).await;
            let latest = actor.get_info(Identifier::Latest).await;
            assert_eq!(latest, Some((2, d2)));

            let block3 = CodedBlock::new(B::new::<Sha256>(d2, 3, 3), coding_config, CONCURRENCY);
            let c3 = block3.commitment();
            let d3 = block3.digest();

            shards.proposed(block3, participants.clone()).await;
            context.sleep(LINK.latency).await;

            let f3 = make_finalization(
                Proposal {
                    round: Round::new(Epoch::zero(), View::new(3)),
                    parent: View::new(2),
                    payload: c3,
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
            let (application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
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
            let block = CodedBlock::new(
                B::new::<Sha256>(parent, 1, 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                CONCURRENCY,
            );
            let commitment = block.commitment();
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            shards.proposed(block.clone(), participants.clone()).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::zero(),
                payload: commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Get by height
            let by_height = actor.get_block(1).await.expect("missing block by height");
            assert_eq!(by_height.height(), 1);
            assert_eq!(by_height.digest(), digest);
            assert_eq!(application.tip(), Some((1, digest)));

            // Get by latest
            let by_latest = actor
                .get_block(Identifier::Latest)
                .await
                .expect("missing block by latest");
            assert_eq!(by_latest.height(), 1);
            assert_eq!(by_latest.digest(), digest);

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
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            // 1) From cache via notarized
            let parent = Sha256::hash(b"");
            let not_block =
                CodedBlock::new(B::new::<Sha256>(parent, 1, 1), coding_config, CONCURRENCY);
            let not_commitment = not_block.commitment();
            let not_digest = not_block.digest();
            let round1 = Round::new(Epoch::zero(), View::new(1));

            shards.proposed(not_block, participants.clone()).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round: round1,
                parent: View::new(1),
                payload: not_commitment,
            };
            let notarization = make_notarization(proposal, &schemes, QUORUM);
            actor.report(Activity::Notarization(notarization)).await;

            let got = actor
                .get_block(&not_digest)
                .await
                .expect("missing block from cache");
            assert_eq!(got.digest(), not_digest);

            // 1) From finalized archive
            let fin_block = CodedBlock::new(
                B::new::<Sha256>(not_digest, 2, 2),
                coding_config,
                CONCURRENCY,
            );
            let fin_commitment = fin_block.commitment();
            let fin_digest = fin_block.digest();
            let round2 = Round::new(Epoch::zero(), View::new(2));

            shards.proposed(fin_block, participants.clone()).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round: round2,
                parent: View::new(1),
                payload: fin_commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;
            let got = actor
                .get_block(&fin_digest)
                .await
                .expect("missing block from finalized archive");
            assert_eq!(got.digest(), fin_digest);
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
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
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
            let block = CodedBlock::new(
                B::new::<Sha256>(parent, 1, 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                CONCURRENCY,
            );
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            shards.proposed(block.clone(), participants.clone()).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::zero(),
                payload: commitment,
            };
            let finalization = make_finalization(proposal, &schemes, QUORUM);
            actor.report(Activity::Finalization(finalization)).await;

            // Get finalization by height
            let finalization = actor
                .get_finalization(1)
                .await
                .expect("missing finalization by height");
            assert_eq!(finalization.proposal.parent, View::zero());
            assert_eq!(
                finalization.proposal.round,
                Round::new(Epoch::zero(), View::new(1))
            );
            assert_eq!(finalization.proposal.payload, commitment);

            assert!(actor.get_finalization(2).await.is_none());
        })
    }

    #[test_traced("WARN")]
    fn test_hint_finalized_triggers_fetch() {
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
            } = bls12381_threshold::fixture::<V, _>(&mut context, NUM_VALIDATORS);

            // Register the initial peer set
            let mut manager = oracle.manager();
            manager
                .update(0, participants.clone().try_into().unwrap())
                .await;

            // Set up two validators
            let (app0, mut actor0, mut shards0, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let (_app1, mut actor1, _, _) = setup_validator(
                context.with_label("validator_1"),
                &mut oracle,
                participants[1].clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;

            // Add links between validators
            setup_network_links(&mut oracle, &participants[..2], LINK).await;

            // Validator 0: Create and finalize blocks 1-5
            let mut parent = Sha256::hash(b"");
            for i in 1..=5u64 {
                let block = CodedBlock::new(
                    B::new::<Sha256>(parent, i, i),
                    coding_config_for_participants(NUM_VALIDATORS as u16),
                    CONCURRENCY,
                );
                let commitment = block.commitment();
                let digest = block.digest();
                let round = Round::new(Epoch::new(0), View::new(i));

                shards0.proposed(block.clone(), participants.clone()).await;
                context.sleep(LINK.latency).await;

                let proposal = Proposal {
                    round,
                    parent: View::new(i - 1),
                    payload: commitment,
                };
                let finalization = make_finalization(proposal, &schemes, QUORUM);
                actor0.report(Activity::Finalization(finalization)).await;

                parent = digest;
            }

            // Wait for validator 0 to process all blocks
            while app0.blocks().len() < 5 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Validator 1 should not have block 5 yet
            assert!(actor1.get_finalization(5).await.is_none());

            // Validator 1: hint that block 5 is finalized, targeting validator 0
            actor1
                .hint_finalized(5, NonEmptyVec::new(participants[0].clone()))
                .await;

            // Wait for the fetch to complete
            while actor1.get_finalization(5).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify validator 1 now has the finalization
            let finalization = actor1
                .get_finalization(5)
                .await
                .expect("finalization should be fetched");
            assert_eq!(finalization.proposal.round.view(), View::new(5));
        })
    }

    #[test_traced("DEBUG")]
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
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            // Finalize blocks at heights 1-5
            let mut parent = Sha256::hash(b"");
            for i in 1..=5 {
                let block =
                    CodedBlock::new(B::new::<Sha256>(parent, i, i), coding_config, CONCURRENCY);
                let commitment = block.commitment();
                let round = Round::new(Epoch::zero(), View::new(i));

                shards.proposed(block.clone(), participants.clone()).await;
                context.sleep(LINK.latency).await;

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
}
