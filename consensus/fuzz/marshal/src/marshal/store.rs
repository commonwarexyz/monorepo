//! Fuzz driver for marshal with prunable finalized archives.

use crate::marshal::end_to_end::twins::{PublicKeyOf, SchemeOf};
use arbitrary::Arbitrary;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Heightable, Reporter as _,
    marshal::{
        Config, Identifier, Start,
        core::{Actor, CommitmentFallback, DigestFallback, Mailbox},
        mocks::{
            application::Application,
            harness::{
                B, BLOCKS_PER_EPOCH, D, NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE,
                QUORUM, StandardHarness, TEST_QUOTA, TestHarness, setup_network_with_participants,
            },
        },
        resolver::p2p as resolver,
        standard::Standard,
        store::{Blocks as StoreBlocks, Certificates as StoreCertificates},
    },
    simplex::types::{Activity, Finalization, Finalize, Proposal},
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{SimplexCertificateMock, simplex::Simplex as _};
use commonware_cryptography::{
    Digestible,
    certificate::{ConstantProvider, Verifier as _},
};
use commonware_macros::select;
use commonware_p2p::{Recipients, simulated::Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Handle, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    archive::{Identifier as ArchiveIdentifier, prunable},
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZU64, NZUsize, non_empty, vec::NonEmptyVec};
use std::{num::NonZeroUsize, time::Duration};

/// The store fuzzer runs on the cheap certificate mock; `K` is unchanged
/// (ed25519), so only the certificate scheme differs from the harness default.
type CertScheme = SchemeOf<SimplexCertificateMock>;
type K = PublicKeyOf<SimplexCertificateMock>;
type StoreVariant = Standard<B>;

/// Certificate-mock port of the harness prunable-validator setup: identical
/// wiring, with the BLS scheme replaced by the certificate mock.
#[allow(clippy::type_complexity)]
async fn setup_prunable_validator_cert_mock(
    context: deterministic::Context,
    oracle: &Oracle<K, deterministic::Context>,
    validator: K,
    schemes: &[CertScheme],
    partition_prefix: &str,
    page_cache: CacheRef,
    unbuffered: bool,
) -> (
    Mailbox<CertScheme, StoreVariant>,
    buffered::Mailbox<K, B>,
    Application<B>,
    Handle<()>,
) {
    let control = oracle.control(validator.clone());
    let provider = ConstantProvider::new(schemes[0].clone());
    let config = Config {
        provider,
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16).into()),
        mailbox_size: MAILBOX_SIZE,
        view_retention: ViewDelta::new(10),
        max_repair: NZUsize!(10),
        max_pending_acks: NZUsize!(1),
        block_codec_config: (),
        partition_prefix: partition_prefix.to_string(),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: page_cache.clone(),
        strategy: Sequential,
    };

    let backfill = control.register(0, TEST_QUOTA).await.unwrap();
    let resolver = resolver::init(
        context.child("resolver"),
        resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill,
    );

    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let network = control.register(1, TEST_QUOTA).await.unwrap();
    broadcast_engine.start(network);

    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        prunable::Config {
            translator: EightCap,
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            key_partition: format!("{partition_prefix}-finalizations-by-height-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalizations-by-height-value"),
            compression: None,
            codec_config: CertScheme::certificate_codec_config_unbounded(),
            items_per_section: NZU64!(10),
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            replay_buffer: config.replay_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");

    let finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        prunable::Config {
            translator: EightCap,
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            key_partition: format!("{partition_prefix}-finalized-blocks-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalized-blocks-value"),
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

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    let application = Application::<B>::default();
    let handle = if unbuffered {
        actor.start_unbuffered(application.clone(), resolver)
    } else {
        actor.start(application.clone(), buffer.clone(), resolver)
    };

    (mailbox, buffer, application, handle)
}

const NUM_BLOCKS: u64 = 16;
const FORCED_OPS: usize = 27;
const MAX_OPS: usize = 96;
const EVENT_SETTLE: Duration = Duration::from_millis(20);
/// Actor mailbox capacity; a burst longer than this spills into the overflow
/// policy that coalesces hints, floors, and prunes.
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(100);

fn block_idx(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=((NUM_BLOCKS - 1) as u8))
}

fn block_index(idx: u8) -> usize {
    (idx as u64 % NUM_BLOCKS) as usize
}

/// Canonical finalization round of `height`. Views advance two per height so
/// every block also has a spare view, above its canonical one and below the
/// next height's, for a finalization at a later view.
fn round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(2 * height.get() - 1))
}

/// The spare view of `height`: a re-proposal finalized after a nullification.
/// A floor at this round stays below the next canonical round, so it neither
/// hides later canonical finalizations nor prunes seeded views above the floor.
fn late_round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(2 * height.get()))
}

fn hint_targets(participants: &[K], selector: u8) -> NonEmptyVec<K> {
    let count = usize::from(selector % 3) + 1;
    let peers = participants
        .iter()
        .skip(1)
        .take(count)
        .cloned()
        .collect::<Vec<_>>();
    NonEmptyVec::try_from(peers).expect("fixture has peers")
}

fn parent_view(height: Height) -> View {
    height
        .previous()
        .filter(|parent| parent.get() > 0)
        .map_or(View::zero(), |parent| round_for_height(parent).view())
}

#[derive(Debug, Clone, Copy)]
pub enum StoreOp {
    SeedBlock {
        block_idx: u8,
    },
    ReportFinalization {
        block_idx: u8,
    },
    GetBlock {
        block_idx: u8,
        by_digest: bool,
    },
    GetInfo {
        block_idx: u8,
        latest: bool,
    },
    GetFinalization {
        block_idx: u8,
    },
    /// `clamp` bounds the height by the processed height so the prune takes
    /// effect; otherwise it may land above the floor and be rejected.
    Prune {
        block_idx: u8,
        clamp: bool,
    },
    /// `late_round` finalizes the block at a view above every canonical round,
    /// so the floor passes the round check even when its height is already
    /// processed.
    SetFloor {
        block_idx: u8,
        late_round: bool,
    },
    HintFinalized {
        block_idx: u8,
        targets: u8,
    },
    /// Enqueues more fire-and-forget messages than the mailbox holds without
    /// yielding, so the tail goes through the overflow policy.
    MessageBurst {
        block_idx: u8,
        count: u8,
    },
    Forward {
        block_idx: u8,
    },
    /// Subscribes to a block and drops the subscription if it is not served
    /// within one settle period.
    Subscribe {
        block_idx: u8,
        by_digest: bool,
    },
    Restart,
    ObserveApplication,
    DirectPutBlock {
        block_idx: u8,
    },
    DirectSyncBlocks,
    DirectGetBlock {
        block_idx: u8,
        by_digest: bool,
    },
    DirectPruneBlocks {
        block_idx: u8,
    },
    DirectMissingBlocks {
        block_idx: u8,
        max: u8,
    },
    DirectLastBlock,
    DirectPutCertificate {
        block_idx: u8,
    },
    DirectSyncCertificates,
    DirectGetCertificate {
        block_idx: u8,
        by_digest: bool,
    },
    DirectPruneCertificates {
        block_idx: u8,
    },
    DirectCertificateRanges {
        block_idx: u8,
    },
    DirectLastCertificate,
}

impl Arbitrary<'_> for StoreOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=189)? {
            0..=24 => Self::SeedBlock {
                block_idx: block_idx(u)?,
            },
            25..=49 => Self::ReportFinalization {
                block_idx: block_idx(u)?,
            },
            50..=61 => Self::GetBlock {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            62..=73 => Self::GetInfo {
                block_idx: block_idx(u)?,
                latest: u.arbitrary()?,
            },
            74..=83 => Self::GetFinalization {
                block_idx: block_idx(u)?,
            },
            84..=91 => Self::Prune {
                block_idx: block_idx(u)?,
                clamp: u.arbitrary()?,
            },
            92..=96 => Self::Restart,
            97..=101 => Self::ObserveApplication,
            102..=109 => Self::DirectPutBlock {
                block_idx: block_idx(u)?,
            },
            110..=115 => Self::DirectSyncBlocks,
            116..=123 => Self::DirectGetBlock {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            124..=129 => Self::DirectPruneBlocks {
                block_idx: block_idx(u)?,
            },
            130..=137 => Self::DirectMissingBlocks {
                block_idx: block_idx(u)?,
                max: u.arbitrary()?,
            },
            138..=141 => Self::DirectLastBlock,
            142..=147 => Self::DirectPutCertificate {
                block_idx: block_idx(u)?,
            },
            148..=151 => Self::DirectSyncCertificates,
            152..=155 => Self::DirectGetCertificate {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            156 => Self::DirectPruneCertificates {
                block_idx: block_idx(u)?,
            },
            157..=158 => Self::DirectCertificateRanges {
                block_idx: block_idx(u)?,
            },
            159 => Self::DirectLastCertificate,
            160..=167 => Self::SetFloor {
                block_idx: block_idx(u)?,
                late_round: u.arbitrary()?,
            },
            168..=175 => Self::HintFinalized {
                block_idx: block_idx(u)?,
                targets: u.arbitrary()?,
            },
            176..=179 => Self::MessageBurst {
                block_idx: block_idx(u)?,
                count: u.arbitrary()?,
            },
            180..=184 => Self::Forward {
                block_idx: block_idx(u)?,
            },
            _ => Self::Subscribe {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct MarshalActorStoreInput {
    pub raw_bytes: Vec<u8>,
    pub ops: Vec<StoreOp>,
    /// Start the actor without a broadcast buffer, so blocks come only from
    /// the cache, the archives, and the resolver.
    pub unbuffered: bool,
}

impl Arbitrary<'_> for MarshalActorStoreInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let extra_ops = u.int_in_range(0..=MAX_OPS - FORCED_OPS)?;
        let mut ops = Vec::with_capacity(FORCED_OPS + extra_ops);
        let forced_ops: [StoreOp; FORCED_OPS] = [
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ReportFinalization { block_idx: 0 },
            StoreOp::GetBlock {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::GetInfo {
                block_idx: 0,
                latest: false,
            },
            StoreOp::GetFinalization { block_idx: 0 },
            StoreOp::ObserveApplication,
            StoreOp::Prune {
                block_idx: 0,
                clamp: true,
            },
            StoreOp::DirectPutBlock { block_idx: 0 },
            StoreOp::DirectPutBlock { block_idx: 2 },
            StoreOp::DirectSyncBlocks,
            StoreOp::DirectGetBlock {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::DirectGetBlock {
                block_idx: 2,
                by_digest: true,
            },
            StoreOp::DirectMissingBlocks {
                block_idx: 0,
                max: 4,
            },
            StoreOp::DirectLastBlock,
            StoreOp::DirectPruneBlocks { block_idx: 15 },
            StoreOp::DirectPutBlock { block_idx: 0 },
            StoreOp::DirectPutCertificate { block_idx: 0 },
            StoreOp::DirectPutCertificate { block_idx: 2 },
            StoreOp::DirectSyncCertificates,
            StoreOp::DirectGetCertificate {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::DirectGetCertificate {
                block_idx: 2,
                by_digest: true,
            },
            StoreOp::DirectCertificateRanges { block_idx: 0 },
            StoreOp::DirectLastCertificate,
            StoreOp::DirectPruneCertificates { block_idx: 15 },
            StoreOp::DirectPutCertificate { block_idx: 0 },
            StoreOp::Restart,
            StoreOp::ObserveApplication,
        ];
        ops.extend(forced_ops);
        for _ in 0..extra_ops {
            ops.push(StoreOp::arbitrary(u)?);
        }
        let unbuffered = u.arbitrary()?;

        let remaining = u.len().min(commonware_consensus_fuzz_core::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self {
            raw_bytes,
            ops,
            unbuffered,
        })
    }
}

fn make_chain() -> Vec<B> {
    let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
    let mut parent = genesis.digest();
    let mut blocks = Vec::with_capacity(NUM_BLOCKS as usize);
    for h in 1..=NUM_BLOCKS {
        let height = Height::new(h);
        let block =
            StandardHarness::make_test_block(parent, parent, height, h, NUM_VALIDATORS as u16);
        parent = block.digest();
        blocks.push(block);
    }
    blocks
}

fn make_finalization(block: &B, schemes: &[CertScheme]) -> Finalization<CertScheme, D> {
    make_finalization_at(block, round_for_height(block.height()), schemes)
}

fn make_finalization_at(
    block: &B,
    round: Round,
    schemes: &[CertScheme],
) -> Finalization<CertScheme, D> {
    let proposal = Proposal::new(round, parent_view(block.height()), block.digest());
    let finalizes: Vec<_> = schemes
        .iter()
        .take(QUORUM as usize)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();
    Finalization::from_finalizes(&schemes[0], non_empty![@&finalizes], &Sequential).unwrap()
}

fn assert_returned_block(block: &B, returned: &B, label: &str) {
    assert_eq!(
        returned.digest(),
        block.digest(),
        "{label} returned wrong digest for height {}",
        block.height().get(),
    );
}

/// Crypto: `SimplexCertificateMock`. Marshal: standard, store driven directly
/// below the wrapper, buffered or unbuffered from fuzz input. Cluster: single
/// validator, prunable archives. Liveness: not checked. App: none (plain
/// delivery sink).
pub fn fuzz_marshal_actor_store(input: MarshalActorStoreInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let unbuffered = input.unbuffered;
    let cfg = deterministic::Config::new().with_rng(rng);
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (participants, schemes) =
            SimplexCertificateMock::setup(&mut context, NAMESPACE, NUM_VALIDATORS);
        let oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;
        let validator = participants[0].clone();
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let partition_prefix = format!("store-fuzz-{validator}");
        let canonical = make_chain();
        let finalizations = canonical
            .iter()
            .map(|block| make_finalization(block, &schemes))
            .collect::<Vec<_>>();

        let mut direct_finalizations = prunable::Archive::init(
            context.child("direct_finalizations"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-direct-finalizations-metadata"),
                key_partition: format!("{partition_prefix}-direct-finalizations-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-direct-finalizations-value"),
                compression: None,
                codec_config: CertScheme::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize direct finalizations archive");
        let mut direct_blocks = prunable::Archive::init(
            context.child("direct_blocks"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-direct-blocks-metadata"),
                key_partition: format!("{partition_prefix}-direct-blocks-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-direct-blocks-value"),
                compression: None,
                codec_config: (),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize direct blocks archive");

        let setup = setup_prunable_validator_cert_mock(
            context.child("validator"),
            &oracle,
            validator.clone(),
            &schemes,
            &partition_prefix,
            page_cache.clone(),
            unbuffered,
        )
        .await;
        let mut application = setup.2;
        let mut mailbox = setup.0;
        let mut actor_handle = setup.3;

        for op in input.ops {
            match op {
                StoreOp::SeedBlock { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    assert!(mailbox.verified(block.context.round, block.clone()).await);
                }
                StoreOp::ReportFinalization { block_idx } => {
                    mailbox.report(Activity::Finalization(
                        finalizations[block_index(block_idx)].clone(),
                    ));
                }
                StoreOp::GetBlock {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        mailbox.get_block(&block.digest()).await
                    } else {
                        mailbox.get_block(block.height()).await
                    };
                    if let Some(returned) = returned {
                        assert_returned_block(block, &returned, "GetBlock");
                    }
                }
                StoreOp::GetInfo { block_idx, latest } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if latest {
                        mailbox.get_info(Identifier::Latest).await
                    } else {
                        mailbox.get_info(block.height()).await
                    };
                    if let Some((height, digest)) = returned
                        && height.get() != 0
                    {
                        let Some(expected) = canonical.get((height.get() - 1) as usize) else {
                            panic!("GetInfo returned unexpected height {}", height.get());
                        };
                        assert_eq!(
                            digest,
                            expected.digest(),
                            "GetInfo returned wrong digest for height {}",
                            height.get(),
                        );
                    }
                }
                StoreOp::GetFinalization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    if let Some(finalization) = mailbox.get_finalization(block.height()).await {
                        assert_eq!(
                            finalization.proposal.payload,
                            block.digest(),
                            "GetFinalization returned wrong payload for height {}",
                            block.height().get(),
                        );
                    }
                }
                StoreOp::Prune { block_idx, clamp } => {
                    let mut height = Height::new(block_index(block_idx) as u64 + 1);
                    if clamp {
                        let processed = mailbox
                            .get_processed()
                            .await
                            .map_or(Height::zero(), |processed| processed.height());
                        height = height.min(processed);
                    }
                    mailbox.prune(height);
                }
                StoreOp::SetFloor {
                    block_idx,
                    late_round,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let finalization = if late_round {
                        make_finalization_at(block, late_round_for_height(block.height()), &schemes)
                    } else {
                        finalizations[block_index(block_idx)].clone()
                    };
                    mailbox.set_floor(finalization);
                }
                StoreOp::HintFinalized { block_idx, targets } => {
                    let height = canonical[block_index(block_idx)].height();
                    mailbox.hint_finalized(height, hint_targets(&participants, targets));
                }
                StoreOp::MessageBurst { block_idx, count } => {
                    let start = block_index(block_idx);
                    for i in 0..MAILBOX_SIZE.get() + 1 + usize::from(count) {
                        let idx = (start + i) % NUM_BLOCKS as usize;
                        let height = canonical[idx].height();
                        match i % 8 {
                            5 => mailbox.prune(height),
                            6 => mailbox.set_floor(finalizations[idx].clone()),
                            7 => {
                                let _ = mailbox
                                    .report(Activity::Finalization(finalizations[idx].clone()));
                            }
                            _ => {
                                mailbox.hint_finalized(height, hint_targets(&participants, i as u8))
                            }
                        }
                    }
                }
                StoreOp::Forward { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let _ = mailbox.forward(block.context.round, block.digest(), Recipients::All);
                }
                StoreOp::Subscribe {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let receiver = if by_digest {
                        mailbox.subscribe_by_digest(block.digest(), DigestFallback::Wait)
                    } else {
                        mailbox.subscribe_by_commitment(
                            block.digest(),
                            CommitmentFallback::FetchByCommitment {
                                height: block.height(),
                            },
                        )
                    };
                    select! {
                        returned = receiver => {
                            if let Ok(returned) = returned {
                                assert_returned_block(block, &returned, "Subscribe");
                            }
                        },
                        _ = context.sleep(EVENT_SETTLE) => {},
                    }
                }
                StoreOp::Restart => {
                    drop(mailbox);
                    drop(application);
                    // Let the actor exit on its closed mailbox, then abort it if it is
                    // still busy so its archives are released before the same
                    // partitions reopen.
                    context.sleep(EVENT_SETTLE).await;
                    actor_handle.abort();
                    let _ = actor_handle.await;
                    let setup = setup_prunable_validator_cert_mock(
                        context.child("validator_restart"),
                        &oracle,
                        validator.clone(),
                        &schemes,
                        &partition_prefix,
                        page_cache.clone(),
                        unbuffered,
                    )
                    .await;
                    application = setup.2;
                    mailbox = setup.0;
                    actor_handle = setup.3;
                }
                StoreOp::ObserveApplication => {
                    let _ = application.tip();
                    let _ = application.blocks();
                    let _ = mailbox.get_processed().await;
                }
                StoreOp::DirectPutBlock { block_idx } => {
                    let block = canonical[block_index(block_idx)].clone();
                    direct_blocks = StoreBlocks::put(direct_blocks, &block)
                        .await
                        .expect("direct block put failed");
                }
                StoreOp::DirectSyncBlocks => {
                    direct_blocks = StoreBlocks::sync(direct_blocks)
                        .await
                        .expect("direct block sync failed");
                }
                StoreOp::DirectGetBlock {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        let digest = block.digest();
                        StoreBlocks::get(&direct_blocks, ArchiveIdentifier::Key(&digest)).await
                    } else {
                        StoreBlocks::get(
                            &direct_blocks,
                            ArchiveIdentifier::Index(block.height().get()),
                        )
                        .await
                    }
                    .expect("direct block get failed");
                    if let Some(returned) = returned {
                        assert_returned_block(block, &returned, "DirectGetBlock");
                    }
                }
                StoreOp::DirectPruneBlocks { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    direct_blocks = StoreBlocks::prune(direct_blocks, height)
                        .await
                        .expect("direct block prune failed");
                }
                StoreOp::DirectMissingBlocks { block_idx, max } => {
                    let start = Height::new(block_index(block_idx) as u64 + 1);
                    let max = usize::from(max % 8) + 1;
                    let missing = StoreBlocks::missing_items(&direct_blocks, start, max);
                    assert!(missing.len() <= max, "too many missing direct blocks");
                }
                StoreOp::DirectLastBlock => {
                    let _ = StoreBlocks::last_index(&direct_blocks);
                }
                StoreOp::DirectPutCertificate { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    direct_finalizations = StoreCertificates::put(
                        direct_finalizations,
                        block.height(),
                        block.digest(),
                        &finalizations[block_index(block_idx)],
                    )
                    .await
                    .expect("direct finalization put failed");
                }
                StoreOp::DirectSyncCertificates => {
                    direct_finalizations = StoreCertificates::sync(direct_finalizations)
                        .await
                        .expect("direct finalization sync failed");
                }
                StoreOp::DirectGetCertificate {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        let digest = block.digest();
                        StoreCertificates::get(
                            &direct_finalizations,
                            ArchiveIdentifier::Key(&digest),
                        )
                        .await
                    } else {
                        StoreCertificates::get(
                            &direct_finalizations,
                            ArchiveIdentifier::Index(block.height().get()),
                        )
                        .await
                    }
                    .expect("direct finalization get failed");
                    if let Some(finalization) = returned {
                        assert_eq!(
                            finalization.proposal.payload,
                            block.digest(),
                            "DirectGetCertificate returned wrong payload for height {}",
                            block.height().get(),
                        );
                    }
                }
                StoreOp::DirectPruneCertificates { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    direct_finalizations = StoreCertificates::prune(direct_finalizations, height)
                        .await
                        .expect("direct finalization prune failed");
                }
                StoreOp::DirectCertificateRanges { block_idx } => {
                    let from = Height::new(block_index(block_idx) as u64);
                    let ranges = StoreCertificates::ranges_from(&direct_finalizations, from)
                        .collect::<Vec<_>>();
                    for (start, end) in ranges {
                        assert!(start <= end, "invalid direct finalization range");
                    }
                }
                StoreOp::DirectLastCertificate => {
                    let _ = StoreCertificates::last_index(&direct_finalizations);
                }
            }
            context.sleep(EVENT_SETTLE).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_script_allows_zero_extra_operations() {
        let bytes = [0u8; 64];
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let input = MarshalActorStoreInput::arbitrary(&mut unstructured).unwrap();
        assert_eq!(input.ops.len(), FORCED_OPS);
        assert!(!input.unbuffered);
    }

    /// Floors, hints, bursts, and effective prunes on both actor start modes.
    #[test]
    fn scripted_floor_hint_and_prune_ops_run() {
        let ops = vec![
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ReportFinalization { block_idx: 0 },
            StoreOp::SeedBlock { block_idx: 1 },
            StoreOp::ReportFinalization { block_idx: 1 },
            StoreOp::SeedBlock { block_idx: 2 },
            StoreOp::ReportFinalization { block_idx: 2 },
            StoreOp::ObserveApplication,
            StoreOp::Prune {
                block_idx: 1,
                clamp: true,
            },
            StoreOp::Prune {
                block_idx: 10,
                clamp: false,
            },
            StoreOp::HintFinalized {
                block_idx: 0,
                targets: 0,
            },
            StoreOp::HintFinalized {
                block_idx: 9,
                targets: 2,
            },
            // Floor at height 6 waits for its anchor, which a later seed supplies.
            StoreOp::SetFloor {
                block_idx: 5,
                late_round: false,
            },
            StoreOp::SeedBlock { block_idx: 5 },
            StoreOp::GetInfo {
                block_idx: 0,
                latest: true,
            },
            StoreOp::GetBlock {
                block_idx: 5,
                by_digest: false,
            },
            StoreOp::GetFinalization { block_idx: 5 },
            // The floor block finalized again at its spare view: a floor whose
            // anchor is already at the processed height.
            StoreOp::SetFloor {
                block_idx: 5,
                late_round: true,
            },
            StoreOp::SeedBlock { block_idx: 5 },
            StoreOp::MessageBurst {
                block_idx: 3,
                count: 40,
            },
            StoreOp::Forward { block_idx: 5 },
            StoreOp::Subscribe {
                block_idx: 5,
                by_digest: true,
            },
            StoreOp::Subscribe {
                block_idx: 9,
                by_digest: false,
            },
            StoreOp::Subscribe {
                block_idx: 12,
                by_digest: true,
            },
            StoreOp::GetBlock {
                block_idx: 5,
                by_digest: true,
            },
            StoreOp::Restart,
            StoreOp::ObserveApplication,
            StoreOp::GetInfo {
                block_idx: 0,
                latest: true,
            },
            StoreOp::SeedBlock { block_idx: 6 },
            StoreOp::ReportFinalization { block_idx: 6 },
            StoreOp::ObserveApplication,
        ];
        for unbuffered in [false, true] {
            fuzz_marshal_actor_store(MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops: ops.clone(),
                unbuffered,
            });
        }
    }

    /// Bursts keep the actor busy past the settle period, so `Restart` has to
    /// stop it before reopening its archives. The burst sizes are the ones from
    /// the campaign input that reopened them while the actor was still alive.
    #[test]
    fn restart_stops_a_busy_actor() {
        let bytes = [0u8; 64];
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let mut ops = MarshalActorStoreInput::arbitrary(&mut unstructured)
            .unwrap()
            .ops;
        ops.extend([
            StoreOp::MessageBurst {
                block_idx: 2,
                count: 13,
            },
            StoreOp::MessageBurst {
                block_idx: 2,
                count: 179,
            },
            StoreOp::Restart,
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ObserveApplication,
        ]);
        for unbuffered in [false, true] {
            fuzz_marshal_actor_store(MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops: ops.clone(),
                unbuffered,
            });
        }
    }
}
