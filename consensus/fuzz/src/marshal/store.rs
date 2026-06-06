//! Fuzz driver for marshal with prunable finalized archives.

use arbitrary::Arbitrary;
use commonware_consensus::{
    marshal::{
        mocks::harness::{
            setup_network_with_participants, StandardHarness, TestHarness, ValidatorHandle, B, D,
            NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE, QUORUM, S, V,
        },
        store::{Blocks as StoreBlocks, Certificates as StoreCertificates},
        Identifier,
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Finalization, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Heightable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, Verifier as _},
    Digestible,
};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Runner, Supervisor as _};
use commonware_storage::{
    archive::{self, prunable, Identifier as ArchiveIdentifier},
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZUsize, NZU64};
use std::time::Duration;

const NUM_BLOCKS: u64 = 16;
const MIN_OPS: usize = 1;
const MAX_OPS: usize = 96;
const EVENT_SETTLE: Duration = Duration::from_millis(20);

fn block_idx(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=((NUM_BLOCKS - 1) as u8))
}

fn block_index(idx: u8) -> usize {
    (idx as u64 % NUM_BLOCKS) as usize
}

fn round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(height.get()))
}

fn parent_view(height: Height) -> View {
    height
        .previous()
        .map(|h| View::new(h.get()))
        .unwrap_or(View::zero())
}

#[derive(Debug, Clone, Copy)]
pub enum StoreOp {
    SeedBlock { block_idx: u8 },
    ReportFinalization { block_idx: u8 },
    GetBlock { block_idx: u8, by_digest: bool },
    GetInfo { block_idx: u8, latest: bool },
    GetFinalization { block_idx: u8 },
    Prune { block_idx: u8 },
    Restart,
    ObserveApplication,
    DirectPutBlock { block_idx: u8 },
    DirectSyncBlocks,
    DirectGetBlock { block_idx: u8, by_digest: bool },
    DirectPruneBlocks { block_idx: u8 },
    DirectMissingBlocks { block_idx: u8, max: u8 },
    DirectLastBlock,
    DirectPutCertificate { block_idx: u8 },
    DirectSyncCertificates,
    DirectGetCertificate { block_idx: u8, by_digest: bool },
    DirectPruneCertificates { block_idx: u8 },
    DirectCertificateRanges { block_idx: u8 },
    DirectLastCertificate,
}

impl Arbitrary<'_> for StoreOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=159)? {
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
            _ => Self::DirectLastCertificate,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MarshalStoreInput {
    pub raw_bytes: Vec<u8>,
    pub ops: Vec<StoreOp>,
}

impl Arbitrary<'_> for MarshalStoreInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let op_count = u.int_in_range(MIN_OPS..=MAX_OPS)?;
        let mut ops = Vec::with_capacity(op_count);
        ops.extend([
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
        ]);
        for _ in ops.len()..op_count {
            ops.push(StoreOp::arbitrary(u)?);
        }

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self { raw_bytes, ops })
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

fn make_finalization(block: &B, schemes: &[S]) -> Finalization<S, D> {
    let proposal = Proposal::new(
        round_for_height(block.height()),
        parent_view(block.height()),
        block.digest(),
    );
    StandardHarness::make_finalization(proposal, schemes, QUORUM)
}

fn assert_returned_block(block: &B, returned: B, label: &str) {
    assert_eq!(
        returned.digest(),
        block.digest(),
        "{label} returned wrong digest for height {}",
        block.height().get(),
    );
}

fn tolerate_pruned_put(result: Result<(), archive::Error>, label: &str) {
    match result {
        Ok(()) | Err(archive::Error::AlreadyPrunedTo(_)) => {}
        Err(e) => panic!("{label}: {e}"),
    }
}

pub fn fuzz_marshal_store(input: MarshalStoreInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
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
                key_partition: format!("{partition_prefix}-direct-finalizations-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-direct-finalizations-value"),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
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

        let setup = StandardHarness::setup_prunable_validator(
            context.child("validator"),
            &oracle,
            validator.clone(),
            &schemes,
            &partition_prefix,
            page_cache.clone(),
        )
        .await;
        let mut application = setup.2;
        let mut handle = ValidatorHandle::<StandardHarness> {
            mailbox: setup.0,
            extra: setup.1,
        };

        for op in input.ops {
            match op {
                StoreOp::SeedBlock { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    StandardHarness::verify_for_prune(&mut handle, block.context.round, block)
                        .await;
                }
                StoreOp::ReportFinalization { block_idx } => {
                    StandardHarness::report_finalization(
                        &mut handle.mailbox,
                        finalizations[block_index(block_idx)].clone(),
                    )
                    .await;
                }
                StoreOp::GetBlock {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        handle.mailbox.get_block(&block.digest()).await
                    } else {
                        handle.mailbox.get_block(block.height()).await
                    };
                    if let Some(returned) = returned {
                        assert_returned_block(block, returned, "GetBlock");
                    }
                }
                StoreOp::GetInfo { block_idx, latest } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if latest {
                        handle.mailbox.get_info(Identifier::Latest).await
                    } else {
                        handle.mailbox.get_info(block.height()).await
                    };
                    if let Some((height, digest)) = returned {
                        if height.get() != 0 {
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
                }
                StoreOp::GetFinalization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    if let Some(finalization) =
                        handle.mailbox.get_finalization(block.height()).await
                    {
                        assert_eq!(
                            finalization.proposal.payload,
                            block.digest(),
                            "GetFinalization returned wrong payload for height {}",
                            block.height().get(),
                        );
                    }
                }
                StoreOp::Prune { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    handle.mailbox.prune(height);
                }
                StoreOp::Restart => {
                    drop(handle);
                    drop(application);
                    context.sleep(EVENT_SETTLE).await;
                    let setup = StandardHarness::setup_prunable_validator(
                        context.child("validator_restart"),
                        &oracle,
                        validator.clone(),
                        &schemes,
                        &partition_prefix,
                        page_cache.clone(),
                    )
                    .await;
                    application = setup.2;
                    handle = ValidatorHandle::<StandardHarness> {
                        mailbox: setup.0,
                        extra: setup.1,
                    };
                }
                StoreOp::ObserveApplication => {
                    let _ = application.tip();
                    let _ = application.blocks();
                    let _ = handle.mailbox.get_processed_height().await;
                }
                StoreOp::DirectPutBlock { block_idx } => {
                    let block = canonical[block_index(block_idx)].clone();
                    tolerate_pruned_put(
                        StoreBlocks::put(&mut direct_blocks, block).await,
                        "direct block put failed",
                    );
                }
                StoreOp::DirectSyncBlocks => {
                    StoreBlocks::sync(&mut direct_blocks)
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
                        assert_returned_block(block, returned, "DirectGetBlock");
                    }
                }
                StoreOp::DirectPruneBlocks { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    StoreBlocks::prune(&mut direct_blocks, height)
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
                    tolerate_pruned_put(
                        StoreCertificates::put(
                            &mut direct_finalizations,
                            block.height(),
                            block.digest(),
                            finalizations[block_index(block_idx)].clone(),
                        )
                        .await,
                        "direct finalization put failed",
                    );
                }
                StoreOp::DirectSyncCertificates => {
                    StoreCertificates::sync(&mut direct_finalizations)
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
                    StoreCertificates::prune(&mut direct_finalizations, height)
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
