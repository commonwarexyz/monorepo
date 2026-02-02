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

mod variant;
pub use variant::Coding;

mod marshaled;
pub use marshaled::{Marshaled, MarshaledConfig};

#[cfg(test)]
mod tests {
    use super::Coding;
    use crate::{
        marshal::{
            coding::{
                shards,
                types::{coding_config_for_participants, CodedBlock, DigestOrCommitment, Shard},
            },
            config::Config,
            core::{Actor, Mailbox},
            mocks::{application::Application, block::Block},
            resolver::p2p as resolver,
            Identifier,
        },
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{Activity, Context, Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{CodingCommitment, Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
        Heightable, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_coding::{CodecConfig, ReedSolomon};
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk,
        certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
        Committable, Digest as _, Digestible, Hasher as _, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle},
        Manager,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Quota, Runner,
    };
    use commonware_storage::{
        archive::{immutable, prunable},
        translator::EightCap,
    };
    use commonware_utils::{vec::NonEmptyVec, NZUsize, Participant, NZU16, NZU64};
    use futures::StreamExt;
    use rand::{
        seq::{IteratorRandom, SliceRandom},
        Rng,
    };
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
        time::{Duration, Instant},
    };
    use tracing::info;

    type H = Sha256;
    type D = Sha256Digest;
    type K = PublicKey;
    type Ctx = Context<D, K>;
    type B = Block<D, Ctx>;
    type V = MinPk;
    type S = bls12381_threshold_vrf::Scheme<K, V>;
    type P = ConstantProvider<S, Epoch>;
    type Variant = Coding<B, ReedSolomon<H>, K>;

    /// Default leader key for tests.
    fn default_leader() -> K {
        PrivateKey::from_seed(0).public_key()
    }

    /// Create a test block with a derived context.
    ///
    /// The context is constructed with:
    /// - Round: epoch 0, view = height
    /// - Leader: default (all zeros)
    /// - Parent: (view = height - 1, commitment = parent)
    fn make_block(parent: D, height: Height, timestamp: u64) -> B {
        let parent_view = height
            .previous()
            .map(|h| View::new(h.get()))
            .unwrap_or(View::zero());
        let context = Ctx {
            round: Round::new(Epoch::zero(), View::new(height.get())),
            leader: default_leader(),
            parent: (parent_view, parent),
        };
        B::new::<Sha256>(context, parent, height, timestamp)
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
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
        Mailbox<S, Variant>,
        shards::Mailbox<B, S, ReedSolomon<H>, K>,
        Height,
    ) {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        // Create the resolver
        let control = oracle.control(validator.clone());
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
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: NZU64!(10),
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
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
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: NZU64!(10),
                codec_config: config.block_codec_config,
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let (shard_engine, shard_mailbox) =
            shards::Engine::new(context.clone(), buffer, (), config.mailbox_size, Sequential);
        shard_engine.start();

        let (actor, mailbox, processed_height) = Actor::init(
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
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        // Generate certificate signatures
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
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
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        // Generate certificate signatures
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
                let block = make_block(parent, Height::new(i), i);
                parent = block.digest();
                let coded_block = CodedBlock::new(block, coding_config, &Sequential);
                blocks.push(coded_block);
            }

            // Broadcast and finalize blocks in random order
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            blocks.shuffle(&mut context);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(
                    !height.is_zero(),
                    "genesis block should not have been generated"
                );

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height.get()));

                // Broadcast block by one validator
                let actor_index: usize = (height.get() % (NUM_VALIDATORS as u64)) as usize;
                let (mut marshal, mut shards) = actors[actor_index].clone();
                shards.proposed(block.clone(), participants.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the shards before continuing.
                context.sleep(link.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.previous().unwrap().get()),
                    payload: block.commitment(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                marshal
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Ask each peer to validate their received shards. This will inform them to broadcast
                // their shards to each other.
                for (i, (_, shards)) in actors.iter_mut().enumerate() {
                    let _recv = shards
                        .subscribe_shard_validity(block.commitment(), Participant::new(i as u32))
                        .await;
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
                            || height.get() == NUM_BLOCKS
                            || height == bounds.last()
                        {
                            actor.report(Activity::Finalization(fin.clone())).await;
                        }
                    }
                } else {
                    // If `quorum_sees_finalization` is not set, finalize randomly with a 20% chance for each
                    // individual participant.
                    for (actor, _) in actors.iter_mut() {
                        if context.gen_bool(0.2)
                            || height.get() == NUM_BLOCKS
                            || height == bounds.last()
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
                    if height.get() < NUM_BLOCKS {
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
                let block = make_block(parent, Height::new(i), i);
                parent = block.digest();
                let coded_block = CodedBlock::new(block, coding_config, &Sequential);
                blocks.push(coded_block);
            }

            // Broadcast and finalize blocks
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(
                    !height.is_zero(),
                    "genesis block should not have been generated"
                );

                // Calculate the epoch and round for the block
                let bounds = epocher.containing(height).unwrap();
                let round = Round::new(bounds.epoch(), View::new(height.get()));

                // Broadcast block by one validator
                let actor_index: usize = (height.get() % (applications.len() as u64)) as usize;
                let (mut marshal, mut shards) = actors[actor_index].clone();
                shards.proposed(block.clone(), participants.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the shards before continuing.
                context.sleep(LINK.latency).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    round,
                    parent: View::new(height.previous().unwrap().get()),
                    payload: block.commitment(),
                };
                let notarization = make_notarization(proposal.clone(), &schemes, QUORUM);
                marshal
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Ask each peer to validate their received shards. This will inform them to broadcast
                // their shards to each other.
                for (i, (_, shards)) in actors.iter_mut().enumerate() {
                    let _recv = shards
                        .subscribe_shard_validity(block.commitment(), Participant::new(i as u32))
                        .await;
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
                    if height.get() < NUM_BLOCKS {
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
            let latest_finalization = second_actor
                .get_finalization(Height::new(NUM_BLOCKS))
                .await
                .unwrap();

            // Set the sync height floor of the first actor to block #100.
            actor.set_floor(Height::new(NEW_SYNC_FLOOR)).await;

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
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    continue;
                }
            }

            // Check that the first actor has blocks from NEW_SYNC_FLOOR onward, but not before.
            for height in 1..=NUM_BLOCKS {
                let block = actor
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

    #[test_traced("WARN")]
    fn test_prune_finalized_archives() {
        let runner = deterministic::Runner::new(
            deterministic::Config::new().with_timeout(Some(Duration::from_secs(120))),
        );
        runner.start(|mut context| async move {
            let oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let validator = participants[0].clone();
            let partition_prefix = format!("prune-test-{}", validator.clone());
            let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
            let control = oracle.control(validator.clone());

            // Closure to initialize marshal with prunable archives
            let init_marshal = |context: deterministic::Context| {
                let ctx = context.clone();
                let validator = validator.clone();
                let schemes = schemes.clone();
                let partition_prefix = partition_prefix.clone();
                let page_cache = page_cache.clone();
                let control = control.clone();
                let oracle_manager = oracle.manager();
                async move {
                    let provider = ConstantProvider::new(schemes[0].clone());
                    let config = Config {
                        provider,
                        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                        mailbox_size: 100,
                        view_retention_timeout: ViewDelta::new(10),
                        max_repair: NZUsize!(10),
                        block_codec_config: (),
                        partition_prefix: partition_prefix.clone(),
                        prunable_items_per_section: NZU64!(10),
                        replay_buffer: NZUsize!(1024),
                        key_write_buffer: NZUsize!(1024),
                        value_write_buffer: NZUsize!(1024),
                        page_cache: page_cache.clone(),
                        strategy: Sequential,
                    };

                    // Create resolver
                    let backfill = control.register(0, TEST_QUOTA).await.unwrap();
                    let resolver_cfg = resolver::Config {
                        public_key: validator.clone(),
                        manager: oracle_manager,
                        blocker: control.clone(),
                        mailbox_size: config.mailbox_size,
                        initial: Duration::from_secs(1),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(100),
                        priority_requests: false,
                        priority_responses: false,
                    };
                    let resolver = resolver::init(&ctx, resolver_cfg, backfill);

                    // Create buffered broadcast engine
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
                    let network = control.register(1, TEST_QUOTA).await.unwrap();
                    broadcast_engine.start(network);

                    let (shard_engine, shard_mailbox) =
                        shards::Engine::<_, S, _, _, B, K, _>::new(
                            context.clone(),
                            buffer,
                            (),
                            config.mailbox_size,
                            Sequential,
                        );
                    shard_engine.start();

                    // Initialize prunable archives
                    let finalizations_by_height = prunable::Archive::init(
                        ctx.with_label("finalizations_by_height"),
                        prunable::Config {
                            translator: EightCap,
                            key_partition: format!(
                                "{}-finalizations-by-height-key",
                                partition_prefix
                            ),
                            key_page_cache: page_cache.clone(),
                            value_partition: format!(
                                "{}-finalizations-by-height-value",
                                partition_prefix
                            ),
                            compression: None,
                            codec_config: S::certificate_codec_config_unbounded(),
                            items_per_section: NZU64!(10),
                            key_write_buffer: config.key_write_buffer,
                            value_write_buffer: config.value_write_buffer,
                            replay_buffer: config.replay_buffer,
                        },
                    )
                    .await
                    .expect("failed to initialize finalizations by height archive");

                    let finalized_blocks = prunable::Archive::init(
                        ctx.with_label("finalized_blocks"),
                        prunable::Config {
                            translator: EightCap,
                            key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                            key_page_cache: page_cache.clone(),
                            value_partition: format!("{}-finalized-blocks-value", partition_prefix),
                            compression: None,
                            codec_config: config.block_codec_config,
                            items_per_section: NZU64!(10),
                            key_write_buffer: config.key_write_buffer,
                            value_write_buffer: config.value_write_buffer,
                            replay_buffer: config.replay_buffer,
                        },
                    )
                    .await
                    .expect("failed to initialize finalized blocks archive");

                    let (actor, mailbox, _processed_height) = Actor::init(
                        ctx.clone(),
                        finalizations_by_height,
                        finalized_blocks,
                        config,
                    )
                    .await;
                    let application = Application::<B>::default();
                    actor.start(application.clone(), shard_mailbox.clone(), resolver);

                    (mailbox, shard_mailbox, application)
                }
            };

            // Initial setup
            let (mut mailbox, mut shards, application) =
                init_marshal(context.with_label("init")).await;

            // Finalize blocks 1-20
            let mut parent = Sha256::hash(b"");
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            for i in 1..=20u64 {
                let block = make_block(parent, Height::new(i), i);
                let block = CodedBlock::new(
                    block,
                    coding_config_for_participants(NUM_VALIDATORS as u16),
                    &Sequential,
                );
                let commitment = block.commitment();
                let digest = block.digest();
                let bounds = epocher.containing(Height::new(i)).unwrap();
                let round = Round::new(bounds.epoch(), View::new(i));

                shards.proposed(block.clone(), participants.clone()).await;
                context.sleep(LINK.latency).await;

                let proposal = Proposal {
                    round,
                    parent: View::new(i - 1),
                    payload: commitment,
                };
                let finalization = make_finalization(proposal, &schemes, QUORUM);
                mailbox.report(Activity::Finalization(finalization)).await;

                parent = digest;
            }

            // Wait for application to process all blocks
            // After this, last_processed_height will be 20
            while application.blocks().len() < 20 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify all blocks are accessible before pruning
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

            // All blocks should still be accessible (prune was ignored)
            mailbox.prune(Height::new(25)).await;
            context.sleep(Duration::from_millis(50)).await;
            for i in 1..=20u64 {
                assert!(
                    mailbox.get_block(Height::new(i)).await.is_some(),
                    "block {i} should still exist after pruning above floor"
                );
            }

            // Pruning at height 10 should prune blocks below 10 (heights 1-9)
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

            // Blocks at or above prune height (10-20) should still be accessible
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

            // Pruning at height 20 should prune blocks 10-19
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

            // Block 20 should still be accessible
            assert!(
                mailbox.get_block(Height::new(20)).await.is_some(),
                "block 20 should still exist"
            );
            assert!(
                mailbox.get_finalization(Height::new(20)).await.is_some(),
                "finalization 20 should still exist"
            );

            // Restart to verify pruning persisted to storage (not just in-memory)
            drop(mailbox);
            let (mut mailbox, _shards, _application) =
                init_marshal(context.with_label("restart")).await;

            // Verify blocks 1-19 are still pruned after restart
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

            // Verify block 20 persisted correctly after restart
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

    #[test_traced("WARN")]
    fn test_subscribe_basic_block_delivery() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let block = make_block(parent, Height::new(1), 1);
            let coded_block = CodedBlock::new(
                block.clone(),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                &Sequential,
            );
            let digest = block.digest();

            let subscription_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(1))), DigestOrCommitment::Digest(digest))
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
            assert_eq!(received_block.height(), Height::new(1));
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let block1 = make_block(parent, Height::new(1), 1);
            let coded_block1 = CodedBlock::new(block1.clone(), coding_config, &Sequential);
            let block2 = make_block(block1.digest(), Height::new(2), 2);
            let coded_block2 = CodedBlock::new(block2.clone(), coding_config, &Sequential);
            let digest1 = block1.digest();
            let digest2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(1))), DigestOrCommitment::Digest(digest1))
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(2))), DigestOrCommitment::Digest(digest2))
                .await;
            let sub3_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(1))), DigestOrCommitment::Digest(digest1))
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
            assert_eq!(received1_sub1.height().get(), 1);
            assert_eq!(received2.height().get(), 2);
            assert_eq!(received1_sub3.height().get(), 1);
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let block1 = make_block(parent, Height::new(1), 1);
            let coded_block1 = CodedBlock::new(block1.clone(), coding_config, &Sequential);
            let block2 = make_block(block1.digest(), Height::new(2), 2);
            let coded_block2 = CodedBlock::new(block2.clone(), coding_config, &Sequential);
            let digest1 = block1.digest();
            let digest2 = block2.digest();

            let sub1_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(1))), DigestOrCommitment::Digest(digest1))
                .await;
            let sub2_rx = actor
                .subscribe(Some(Round::new(Epoch::zero(), View::new(2))), DigestOrCommitment::Digest(digest2))
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
            assert_eq!(received2.height().get(), 2);
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let block1 = CodedBlock::new(
                make_block(parent, Height::new(1), 1),
                coding_config,
                &Sequential,
            );
            let block2 = CodedBlock::new(
                make_block(block1.digest(), Height::new(2), 2),
                coding_config,
                &Sequential,
            );
            let block3 = CodedBlock::new(
                make_block(block2.digest(), Height::new(3), 3),
                coding_config,
                &Sequential,
            );

            let sub1_rx = actor.subscribe(None, DigestOrCommitment::Digest(block1.digest())).await;
            let sub2_rx = actor.subscribe(None, DigestOrCommitment::Digest(block2.digest())).await;
            let sub3_rx = actor.subscribe(None, DigestOrCommitment::Digest(block3.digest())).await;

            // Block1: Broadcasted and notarized by the actor
            shards.proposed(block1.clone(), participants.clone()).await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block1.commitment(), Participant::new(i as u32))
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
            assert_eq!(received1.height().get(), 1);

            // Block2: Broadcasted and finalized by the actor
            shards.proposed(block2.clone(), participants.clone()).await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block2.commitment(), Participant::new(i as u32))
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
            assert_eq!(received2.height().get(), 2);

            // Block3: Broadcasted by a remote actor
            let (_, mut remote_shards) = actors[1].clone();
            remote_shards
                .proposed(block3.clone(), participants.clone())
                .await;
            context.sleep(LINK.latency * 2).await;

            // Have each peer validate their received shards
            for (i, (_, shards)) in actors.iter_mut().enumerate() {
                let _recv = shards
                    .subscribe_shard_validity(block3.commitment(), Participant::new(i as u32))
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
            assert_eq!(received3.height().get(), 3);
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            assert!(actor.get_info(Height::new(1)).await.is_none());

            // Create and verify a block, then finalize it
            let parent = Sha256::hash(b"");
            let block = CodedBlock::new(
                make_block(parent, Height::new(1), 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                &Sequential,
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
            assert_eq!(
                actor.get_info(Identifier::Latest).await,
                Some((Height::new(1), digest))
            );

            // Height 1 now present
            assert_eq!(
                actor.get_info(Height::new(1)).await,
                Some((Height::new(1), digest))
            );

            // Commitment should map to its height
            assert_eq!(
                actor.get_info(&digest).await,
                Some((Height::new(1), digest))
            );

            // Missing height
            assert!(actor.get_info(Height::new(2)).await.is_none());

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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let block1 = CodedBlock::new(
                make_block(parent0, Height::new(1), 1),
                coding_config,
                &Sequential,
            );
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
            assert_eq!(latest, Some((Height::new(1), d1)));

            let block2 = CodedBlock::new(
                make_block(d1, Height::new(2), 2),
                coding_config,
                &Sequential,
            );
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
            assert_eq!(latest, Some((Height::new(2), d2)));

            let block3 = CodedBlock::new(
                make_block(d2, Height::new(3), 3),
                coding_config,
                &Sequential,
            );
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
            assert_eq!(latest, Some((Height::new(3), d3)));
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
                make_block(parent, Height::new(1), 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                &Sequential,
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
            let by_height = actor
                .get_block(Height::new(1))
                .await
                .expect("missing block by height");
            assert_eq!(by_height.height().get(), 1);
            assert_eq!(by_height.digest(), digest);
            assert_eq!(application.tip(), Some((Height::new(1), digest)));

            // Get by latest
            let by_latest = actor
                .get_block(Identifier::Latest)
                .await
                .expect("missing block by latest");
            assert_eq!(by_latest.height().get(), 1);
            assert_eq!(by_latest.digest(), digest);

            // Missing height
            let by_height = actor.get_block(Height::new(2)).await;
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
            let not_block = CodedBlock::new(
                make_block(parent, Height::new(1), 1),
                coding_config,
                &Sequential,
            );
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
                make_block(not_digest, Height::new(2), 2),
                coding_config,
                &Sequential,
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
            assert_eq!(got.height().get(), 2);

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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let (_application, mut actor, mut shards, _) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            // Before any finalization, get_finalization should be None
            let finalization = actor.get_finalization(Height::new(1)).await;
            assert!(finalization.is_none());

            // Finalize a block at height 1
            let parent = Sha256::hash(b"");
            let block = CodedBlock::new(
                make_block(parent, Height::new(1), 1),
                coding_config_for_participants(NUM_VALIDATORS as u16),
                &Sequential,
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
                .get_finalization(Height::new(1))
                .await
                .expect("missing finalization by height");
            assert_eq!(finalization.proposal.parent, View::zero());
            assert_eq!(
                finalization.proposal.round,
                Round::new(Epoch::zero(), View::new(1))
            );
            assert_eq!(finalization.proposal.payload, commitment);

            assert!(actor.get_finalization(Height::new(2)).await.is_none());
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
                    make_block(parent, Height::new(i), i),
                    coding_config_for_participants(NUM_VALIDATORS as u16),
                    &Sequential,
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
            assert!(actor1.get_finalization(Height::new(5)).await.is_none());

            // Validator 1: hint that block 5 is finalized, targeting validator 0
            actor1
                .hint_finalized(Height::new(5), NonEmptyVec::new(participants[0].clone()))
                .await;

            // Wait for the fetch to complete
            while actor1.get_finalization(Height::new(5)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify validator 1 now has the finalization
            let finalization = actor1
                .get_finalization(Height::new(5))
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

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
                let block = CodedBlock::new(
                    make_block(parent, Height::new(i), i),
                    coding_config,
                    &Sequential,
                );
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
                assert_eq!(blocks[i].height().get(), 5 - i as u64);
            });
        })
    }

    // =============================================================================================
    // Marshaled wrapper tests (ported from standard marshal)
    // =============================================================================================

    use crate::{
        marshal::{
            ancestry::{AncestorStream, AncestryProvider},
            coding::{Marshaled, MarshaledConfig},
        },
        Automaton, CertifiableAutomaton, VerifyingApplication,
    };
    use commonware_macros::select;

    /// Block type for Marshaled tests that embeds a CodingCommitment-based context.
    ///
    /// The coding `Marshaled` wrapper requires blocks to have `Context<CodingCommitment, K>`
    /// as their context type, not `Context<D, K>`.
    type CodingCtx = Context<CodingCommitment, K>;
    type CodingB = Block<D, CodingCtx>;
    type CodingVariant = Coding<CodingB, ReedSolomon<H>, K>;

    /// Create a test block with a CodingCommitment-based context.
    fn make_coding_block(context: CodingCtx, parent: D, height: Height, timestamp: u64) -> CodingB {
        CodingB::new::<Sha256>(context, parent, height, timestamp)
    }

    /// Genesis blocks use a special coding config that doesn't actually encode.
    const GENESIS_CODING_CONFIG: commonware_coding::Config = commonware_coding::Config {
        minimum_shards: 0,
        extra_shards: 0,
    };

    /// Create a genesis CodingCommitment (all zeros for digests, genesis config).
    fn genesis_commitment() -> CodingCommitment {
        CodingCommitment::from((D::EMPTY, D::EMPTY, GENESIS_CODING_CONFIG))
    }

    /// Setup function for Marshaled tests that creates infrastructure for CodingB blocks.
    ///
    /// This is similar to `setup_validator` but uses blocks with `Context<CodingCommitment, K>`
    /// as their context type, which is required by the `Marshaled` wrapper.
    async fn setup_marshaled_test_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        partition_prefix: &str,
    ) -> (
        Application<CodingB>,
        Mailbox<S, CodingVariant>,
        shards::Mailbox<CodingB, S, ReedSolomon<H>, K>,
        Height,
    ) {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        // Create the resolver
        let control = oracle.control(validator.clone());
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
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: NZU64!(10),
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        // Initialize finalized blocks
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
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: NZU64!(10),
                codec_config: config.block_codec_config,
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (shard_engine, shard_mailbox) =
            shards::Engine::new(context.clone(), buffer, (), config.mailbox_size, Sequential);
        shard_engine.start();

        let (actor, mailbox, processed_height) = Actor::init(
            context.clone(),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<CodingB>::default();

        // Start the application
        actor.start(application.clone(), shard_mailbox.clone(), resolver);

        (application, mailbox, shard_mailbox, processed_height)
    }

    /// Test that certifying a lower-view block after a higher-view block succeeds.
    ///
    /// This is a critical test for crash recovery scenarios where a validator may need
    /// to certify blocks in non-sequential view order.
    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: CodingB,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = CodingB;
            type Context = CodingCtx;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> bool {
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let (_base_app, marshal, shards, _processed_height) = setup_marshaled_test_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
                "test_certify_lower_view",
            )
            .await;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
                partition_prefix: "test_certify_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

            // Create parent block at height 1
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(0), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards
                .clone()
                .proposed(coded_parent, participants.clone())
                .await;

            // Block A at view 5 (height 2) - create with context matching what verify will receive
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = CodingCtx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = make_coding_block(context_a.clone(), parent_digest, Height::new(2), 200);
            let coded_block_a = CodedBlock::new(block_a.clone(), coding_config, &Sequential);
            let commitment_a = coded_block_a.commitment();
            shards
                .clone()
                .proposed(coded_block_a, participants.clone())
                .await;

            // Block B at view 10 (height 2, different block same height - could happen with
            // different proposers or re-proposals)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = CodingCtx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_b = make_coding_block(context_b.clone(), parent_digest, Height::new(2), 300);
            let coded_block_b = CodedBlock::new(block_b.clone(), coding_config, &Sequential);
            let commitment_b = coded_block_b.commitment();
            shards
                .clone()
                .proposed(coded_block_b, participants.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Step 1: Verify block A at view 5
            let _ = marshaled.verify(context_a, commitment_a).await.await;

            // Step 2: Verify block B at view 10
            let _ = marshaled.verify(context_b, commitment_b).await.await;

            // Step 3: Certify block B at view 10 FIRST
            let certify_b = marshaled.certify(round_b, commitment_b).await;
            assert!(
                certify_b.await.unwrap(),
                "Block B certification should succeed"
            );

            // Step 4: Certify block A at view 5 - should succeed
            let certify_a = marshaled.certify(round_a, commitment_a).await;

            // Use select with timeout to detect never-resolving receiver
            select! {
                result = certify_a => {
                    assert!(
                        result.unwrap(),
                        "Block A certification should succeed"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("Block A certification timed out");
                },
            }
        })
    }

    /// Regression test for re-proposal validation in optimistic_verify.
    ///
    /// Verifies that:
    /// 1. Valid re-proposals at epoch boundaries are accepted
    /// 2. Invalid re-proposals (not at epoch boundary) are rejected
    ///
    /// A re-proposal occurs when the parent digest equals the block being verified,
    /// meaning the same block is being proposed again in a new view.
    #[test_traced("INFO")]
    fn test_marshaled_reproposal_validation() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: CodingB,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = CodingB;
            type Context = CodingCtx;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> bool {
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let (_base_app, marshal, shards, _processed_height) = setup_marshaled_test_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
                "test_reproposal",
            )
            .await;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
                partition_prefix: "test_reproposal_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

            // Build a chain up to the epoch boundary (height 19 is the last block in epoch 0
            // with BLOCKS_PER_EPOCH=20, since epoch 0 covers heights 0-19)
            let mut parent = genesis.digest();
            let mut last_view = View::zero();
            let mut last_commitment = genesis_commitment();
            for i in 1..BLOCKS_PER_EPOCH.get() {
                let round = Round::new(Epoch::new(0), View::new(i));
                let ctx = CodingCtx {
                    round,
                    leader: me.clone(),
                    parent: (last_view, last_commitment),
                };
                let block = make_coding_block(ctx.clone(), parent, Height::new(i), i * 100);
                let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
                last_commitment = coded_block.commitment();
                shards
                    .clone()
                    .proposed(coded_block, participants.clone())
                    .await;
                parent = block.digest();
                last_view = View::new(i);
            }

            // Create the epoch boundary block (height 19, last block in epoch 0)
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::new(0), View::new(boundary_height.get()));
            let boundary_context = CodingCtx {
                round: boundary_round,
                leader: me.clone(),
                parent: (last_view, last_commitment),
            };
            let boundary_block = make_coding_block(
                boundary_context.clone(),
                parent,
                boundary_height,
                boundary_height.get() * 100,
            );
            let coded_boundary =
                CodedBlock::new(boundary_block.clone(), coding_config, &Sequential);
            let boundary_commitment = coded_boundary.commitment();
            shards
                .clone()
                .proposed(coded_boundary, participants.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Test 1: Valid re-proposal at epoch boundary should be accepted
            // Re-proposal context: parent digest equals the block being verified
            // Re-proposals happen within the same epoch when the parent is the last block
            //
            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We call verify() to register the verification task,
            // then certify() returns the deferred_verify result.
            let reproposal_round = Round::new(Epoch::new(0), View::new(20));
            let reproposal_context = CodingCtx {
                round: reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment), // Parent IS the boundary block
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(reproposal_context.clone(), boundary_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                certify_result.unwrap(),
                "Valid re-proposal at epoch boundary should be accepted"
            );

            // Test 2: Invalid re-proposal (not at epoch boundary) should be rejected
            // Create a block at height 10 (not at epoch boundary)
            let non_boundary_height = Height::new(10);
            let non_boundary_round = Round::new(Epoch::new(0), View::new(10));
            // For simplicity, we'll create a fresh non-boundary block and test re-proposal
            let non_boundary_context = CodingCtx {
                round: non_boundary_round,
                leader: me.clone(),
                parent: (View::new(9), last_commitment), // Use a prior commitment
            };
            let non_boundary_block = make_coding_block(
                non_boundary_context.clone(),
                parent,
                non_boundary_height,
                1000,
            );
            let coded_non_boundary =
                CodedBlock::new(non_boundary_block.clone(), coding_config, &Sequential);
            let non_boundary_commitment = coded_non_boundary.commitment();

            // Make the non-boundary block available
            shards
                .clone()
                .proposed(coded_non_boundary, participants.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = CodingCtx {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(invalid_reproposal_context, non_boundary_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(invalid_reproposal_round, non_boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Invalid re-proposal (not at epoch boundary) should be rejected"
            );

            // Test 3: Re-proposal with mismatched epoch should be rejected
            // This is a regression test - re-proposals must be in the same epoch as the block.
            let cross_epoch_reproposal_round = Round::new(Epoch::new(1), View::new(20));
            let cross_epoch_reproposal_context = CodingCtx {
                round: cross_epoch_reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(cross_epoch_reproposal_context.clone(), boundary_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(cross_epoch_reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Re-proposal with mismatched epoch should be rejected"
            );

            // Note: Tests for certify-only paths (crash recovery scenarios) are not included here
            // because they require multiple validators to reconstruct blocks from shards. In a
            // single-validator test setup, block reconstruction fails due to insufficient shards.
            // These paths are tested in integration tests with multiple validators.
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: CodingB,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = CodingB;
            type Context = CodingCtx;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> bool {
                true
            }
        }

        #[derive(Clone)]
        struct LimitedEpocher {
            inner: FixedEpocher,
            max_epoch: u64,
        }

        impl Epocher for LimitedEpocher {
            fn containing(&self, height: Height) -> Option<crate::types::EpochInfo> {
                let bounds = self.inner.containing(height)?;
                if bounds.epoch().get() > self.max_epoch {
                    None
                } else {
                    Some(bounds)
                }
            }

            fn first(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.first(epoch)
                }
            }

            fn last(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.last(epoch)
                }
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let (_base_app, marshal, shards, _processed_height) = setup_marshaled_test_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
                "test_unsupported_epoch",
            )
            .await;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: limited_epocher,
                strategy: Sequential,
                partition_prefix: "test_unsupported_epoch_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards
                .clone()
                .proposed(coded_parent, participants.clone())
                .await;

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: default_leader(),
                parent: (View::new(19), parent_commitment),
            };
            let block = make_coding_block(block_ctx, parent_digest, Height::new(20), 2000);
            let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
            let block_commitment = coded_block.commitment();
            shards
                .clone()
                .proposed(coded_block, participants.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We need to use certify() to get the deferred_verify result.
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = CodingCtx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(unsupported_context, block_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(unsupported_round, block_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Block in unsupported epoch should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry() {
        #[derive(Clone)]
        struct MockVerifyingApp {
            genesis: CodingB,
        }

        impl crate::Application<deterministic::Context> for MockVerifyingApp {
            type Block = CodingB;
            type Context = CodingCtx;
            type SigningScheme = S;

            async fn genesis(&mut self) -> Self::Block {
                self.genesis.clone()
            }

            async fn propose<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
            ) -> Option<Self::Block> {
                None
            }
        }

        impl VerifyingApplication<deterministic::Context> for MockVerifyingApp {
            async fn verify<A: AncestryProvider<Block = Self::Block>>(
                &mut self,
                _context: (deterministic::Context, Self::Context),
                _ancestry: AncestorStream<A, Self::Block>,
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
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let me = participants[0].clone();
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let (_base_app, marshal, shards, _) = setup_marshaled_test_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
                "test_invalid_ancestry",
            )
            .await;

            // Create genesis block
            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Wrap with Marshaled verifier
            let mock_app = MockVerifyingApp {
                genesis: genesis.clone(),
            };
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
                partition_prefix: "test_invalid_ancestry_marshaled".to_string(),
            };
            let mut marshaled = Marshaled::init(context.clone(), cfg).await;

            // Test case 1: Non-contiguous height
            //
            // We need both blocks in the same epoch.
            // With BLOCKS_PER_EPOCH=20: epoch 0 is heights 0-19, epoch 1 is heights 20-39
            //
            // Store honest parent at height 21 (epoch 1)
            let honest_parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(21)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let honest_parent = make_coding_block(
                honest_parent_ctx,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 1),
                1000,
            );
            let parent_digest = honest_parent.digest();
            let coded_parent = CodedBlock::new(honest_parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards
                .clone()
                .proposed(coded_parent, participants.clone())
                .await;

            // Byzantine proposer broadcasts malicious block at height 35
            // In reality this would come via buffered broadcast, but for test simplicity
            // we call broadcast() directly which makes it available for subscription
            let malicious_ctx1 = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(35)),
                leader: default_leader(),
                parent: (View::new(21), parent_commitment),
            };
            let malicious_block = make_coding_block(
                malicious_ctx1,
                parent_digest,
                Height::new(BLOCKS_PER_EPOCH.get() + 15),
                2000,
            );
            let coded_malicious =
                CodedBlock::new(malicious_block.clone(), coding_config, &Sequential);
            let malicious_commitment = coded_malicious.commitment();
            shards
                .clone()
                .proposed(coded_malicious, participants.clone())
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 35
            //
            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We need to use certify() to get the deferred_verify result.
            let byzantine_round = Round::new(Epoch::new(1), View::new(35));
            let byzantine_context = CodingCtx {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round, malicious_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent commitment
            //
            // Create another malicious block with correct height but invalid parent commitment
            let malicious_ctx2 = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(22)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()), // Claims genesis as parent
            };
            let malicious_block2 = make_coding_block(
                malicious_ctx2,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let coded_malicious2 =
                CodedBlock::new(malicious_block2.clone(), coding_config, &Sequential);
            let malicious_commitment2 = coded_malicious2.commitment();
            shards
                .clone()
                .proposed(coded_malicious2, participants.clone())
                .await;

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Consensus determines parent should be block at height 21
            // and calls verify on the Marshaled automaton with a block at height 22
            let byzantine_round2 = Round::new(Epoch::new(1), View::new(22));
            let byzantine_context2 = CodingCtx {
                round: byzantine_round2,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 4. Validate parent commitment matches (fail)
            // 5. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context2, malicious_commitment2)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round2, malicious_commitment2)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    // =============================================================================================
    // Additional Actor-level tests (ported from standard marshal)
    // =============================================================================================

    #[test_traced("WARN")]
    fn test_finalize_same_height_different_views() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            // Set up two validators
            let mut actors = Vec::new();
            let mut shard_actors = Vec::new();
            for (i, validator) in participants.iter().enumerate().take(2) {
                let (_app, actor, shards, _) = setup_validator(
                    context.with_label(&format!("validator_{i}")),
                    &mut oracle,
                    validator.clone(),
                    ConstantProvider::new(schemes[i].clone()),
                )
                .await;
                actors.push(actor);
                shard_actors.push(shards);
            }

            // Create block at height 1
            let parent = Sha256::hash(b"");
            let block = make_block(parent, Height::new(1), 1);
            let digest = block.digest();
            let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
            let commitment = coded_block.commitment();

            // Both validators broadcast the block via shards
            // In coding marshal, blocks become available through shard reconstruction
            shard_actors[0]
                .clone()
                .proposed(coded_block.clone(), participants.clone())
                .await;
            shard_actors[1]
                .clone()
                .proposed(coded_block.clone(), participants.clone())
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
            let block0 = actors[0].get_block(Height::new(1)).await.unwrap();
            let block1 = actors[1].get_block(Height::new(1)).await.unwrap();
            assert_eq!(block0.digest(), block.digest());
            assert_eq!(block1.digest(), block.digest());

            // Verify both validators have finalizations stored
            let fin0 = actors[0].get_finalization(Height::new(1)).await.unwrap();
            let fin1 = actors[1].get_finalization(Height::new(1)).await.unwrap();

            // Verify the finalizations have the expected different views
            assert_eq!(fin0.proposal.payload, commitment);
            assert_eq!(fin0.round().view(), View::new(1));
            assert_eq!(fin1.proposal.payload, commitment);
            assert_eq!(fin1.round().view(), View::new(2));

            // Both validators can retrieve block by height
            assert_eq!(
                actors[0].get_info(Height::new(1)).await,
                Some((Height::new(1), digest))
            );
            assert_eq!(
                actors[1].get_info(Height::new(1)).await,
                Some((Height::new(1), digest))
            );

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
            let fin0_after = actors[0].get_finalization(Height::new(1)).await.unwrap();
            assert_eq!(fin0_after.round().view(), View::new(1));

            // Validator 1 should still have the original finalization (v2)
            let fin1_after = actors[1].get_finalization(Height::new(1)).await.unwrap();
            assert_eq!(fin1_after.round().view(), View::new(2));
        })
    }

    #[test_traced("WARN")]
    fn test_init_processed_height() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            // Test 1: Fresh init should return processed height 0
            let me = participants[0].clone();
            let (application, mut actor, mut shards, initial_height) = setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            assert_eq!(initial_height.get(), 0);

            // Process multiple blocks (1, 2, 3)
            let mut parent = Sha256::hash(b"");
            let mut blocks = Vec::new();
            for i in 1..=3 {
                let block = make_block(parent, Height::new(i), i);
                let digest = block.digest();
                let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::new(0), View::new(i));

                shards.proposed(coded_block, participants.clone()).await;
                // In coding marshal, blocks become available through shard reconstruction
                // when notarization/finalization is reported
                let proposal = Proposal {
                    round,
                    parent: View::new(i - 1),
                    payload: commitment,
                };
                let finalization = make_finalization(proposal, &schemes, QUORUM);
                actor.report(Activity::Finalization(finalization)).await;

                blocks.push(block);
                parent = digest;
            }

            // Wait for application to process all blocks
            while application.blocks().len() < 3 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Set marshal's processed height to 3
            actor.set_floor(Height::new(3)).await;
            context.sleep(Duration::from_millis(10)).await;

            // Verify application received all blocks
            assert_eq!(application.blocks().len(), 3);
            assert_eq!(
                application.tip(),
                Some((Height::new(3), blocks[2].digest()))
            );

            // Test 2: Restart with marshal processed height = 3
            let (_restart_application, _restart_actor, _restart_shards, restart_height) =
                setup_validator(
                    context.with_label("validator_0_restart"),
                    &mut oracle,
                    me,
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;

            assert_eq!(restart_height.get(), 3);
        })
    }
}
