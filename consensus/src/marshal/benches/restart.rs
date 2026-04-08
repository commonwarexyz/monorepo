use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Error, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, ReedSolomon};
use commonware_consensus::{
    marshal::{
        coding::{
            types::{coding_config_for_participants, CodedBlock, StoredCodedBlock},
            Coding,
        },
        core::Actor,
        standard::Standard,
        store::{Blocks as BlockStore, Certificates as CertificateStore},
        Config as MarshalConfig,
    },
    simplex::{
        mocks::scheme::Scheme as MockScheme,
        types::{Context as SimplexContext, Finalization, Finalize, Proposal},
    },
    types::{coding::Commitment, Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    certificate::{mocks::Shared, ConstantProvider},
    ed25519::{PrivateKey, PublicKey},
    sha256::{Digest as Sha256Digest, Sha256},
    Committable, Digest as _, Digestible, Hasher as _, Signer as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    benchmarks::{context, tokio as bench_tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context as RuntimeContext, Runner as TokioRunner},
    Metrics as _, Runner,
};
use commonware_storage::{
    archive::immutable,
    metadata::{self, Metadata},
};
use commonware_utils::{ordered::Set, sequence::U64, NZUsize, Participant, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use std::{
    hint::black_box,
    io::ErrorKind,
    num::{NonZeroU16, NonZeroUsize},
    time::{Duration, Instant},
};

const LATEST_KEY: U64 = U64::new(0xFF);
const NAMESPACE: &[u8] = b"marshal-bench-restart";
const PARTICIPANTS: u32 = 4;
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(1024);
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024;

#[cfg(not(full_bench))]
const BLOCKS: [u64; 2] = [1_000, 10_000];
#[cfg(full_bench)]
const BLOCKS: [u64; 3] = [1_000, 10_000, 25_000];

type Scheme = MockScheme<PublicKey>;
type Provider = ConstantProvider<Scheme, Epoch>;
type StandardBlock = BenchBlock<()>;
type StandardVariant = Standard<StandardBlock>;
type StandardCertificates =
    immutable::Archive<RuntimeContext, Sha256Digest, Finalization<Scheme, Sha256Digest>>;
type StandardBlocks = immutable::Archive<RuntimeContext, Sha256Digest, StandardBlock>;
type CodingContext = SimplexContext<Commitment, PublicKey>;
type InnerCodingBlock = BenchBlock<CodingContext>;
type CodingBlock = CodedBlock<InnerCodingBlock, ReedSolomon<Sha256>, Sha256>;
type StoredCodingBlock = StoredCodedBlock<InnerCodingBlock, ReedSolomon<Sha256>, Sha256>;
type CodingVariant = Coding<InnerCodingBlock, ReedSolomon<Sha256>, Sha256, PublicKey>;
type CodingCertificates =
    immutable::Archive<RuntimeContext, Sha256Digest, Finalization<Scheme, Commitment>>;
type CodingBlocks = immutable::Archive<RuntimeContext, Sha256Digest, StoredCodingBlock>;

#[derive(Clone, Copy)]
enum Variant {
    Standard,
    Coding,
}

impl Variant {
    const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Coding => "coding",
        }
    }
}

#[derive(Clone)]
struct MockConsensus {
    leader: PublicKey,
    signers: Vec<Scheme>,
    verifier: Scheme,
    coding_config: CodingConfig,
}

impl MockConsensus {
    fn new() -> Self {
        let participants = Set::from_iter_dedup(
            (0..PARTICIPANTS).map(|index| PrivateKey::from_seed(u64::from(index)).public_key()),
        );
        let shared = Shared::default();
        let signers = (0..PARTICIPANTS)
            .map(|index| {
                Scheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    Participant::new(index),
                    shared.clone(),
                )
                .expect("participant must have a signer")
            })
            .collect();
        let verifier = Scheme::verifier(NAMESPACE, participants.clone(), shared);

        Self {
            leader: participants[0].clone(),
            signers,
            verifier,
            coding_config: coding_config_for_participants(PARTICIPANTS as u16),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BenchBlock<C> {
    context: C,
    parent: Sha256Digest,
    height: Height,
    timestamp: u64,
    digest: Sha256Digest,
}

impl<C: Codec<Cfg = ()>> BenchBlock<C> {
    fn compute_digest(
        context: &C,
        parent: &Sha256Digest,
        height: Height,
        timestamp: u64,
    ) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(parent.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&context.encode());
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    }

    fn new(context: C, parent: Sha256Digest, height: Height, timestamp: u64) -> Self {
        let digest = Self::compute_digest(&context, &parent, height, timestamp);
        Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        }
    }
}

impl<C: Write> Write for BenchBlock<C> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<C: Read<Cfg = ()>> Read for BenchBlock<C> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = C::read(reader)?;
        let parent = Sha256Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();
        let digest = Sha256Digest::read(reader)?;
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        })
    }
}

impl<C: EncodeSize> EncodeSize for BenchBlock<C> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<C: Clone + Send + Sync + 'static> Digestible for BenchBlock<C> {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl<C: Clone + Send + Sync + 'static> Heightable for BenchBlock<C> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> Block for BenchBlock<C> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> CertifiableBlock for BenchBlock<C> {
    type Context = C;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

fn make_finalization<C: commonware_cryptography::Digest>(
    consensus: &MockConsensus,
    round: Round,
    parent: View,
    commitment: C,
) -> Finalization<Scheme, C> {
    let proposal = Proposal::new(round, parent, commitment);
    let finalizes = consensus
        .signers
        .iter()
        .map(|scheme| {
            Finalize::sign(scheme, proposal.clone()).expect("mock scheme signer must sign")
        })
        .collect::<Vec<_>>();
    Finalization::from_finalizes(&consensus.verifier, &finalizes, &Sequential)
        .expect("quorum of finalize votes must assemble")
}

fn immutable_archive_config<Cfg>(
    partition_prefix: &str,
    name: &str,
    page_cache: CacheRef,
    codec_config: Cfg,
) -> immutable::Config<Cfg> {
    immutable::Config {
        metadata_partition: format!("{partition_prefix}-{name}-metadata"),
        freezer_table_partition: format!("{partition_prefix}-{name}-freezer-table"),
        freezer_table_initial_size: 4_096,
        freezer_table_resize_frequency: 4,
        freezer_table_resize_chunk_size: 1_024,
        freezer_key_partition: format!("{partition_prefix}-{name}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{partition_prefix}-{name}-freezer-value"),
        freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
        freezer_value_compression: None,
        ordinal_partition: format!("{partition_prefix}-{name}-ordinal"),
        items_per_section: ITEMS_PER_SECTION,
        freezer_key_write_buffer: WRITE_BUFFER,
        freezer_value_write_buffer: WRITE_BUFFER,
        ordinal_write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
        codec_config,
    }
}

fn actor_config<B: Block<Cfg = ()>>(
    partition_prefix: &str,
    page_cache: CacheRef,
    provider: Provider,
) -> MarshalConfig<B, Provider, FixedEpocher, Sequential> {
    MarshalConfig {
        provider,
        epocher: FixedEpocher::new(NZU64!(1_000_000)),
        partition_prefix: partition_prefix.to_string(),
        mailbox_size: 128,
        view_retention_timeout: ViewDelta::new(10),
        prunable_items_per_section: ITEMS_PER_SECTION,
        page_cache,
        replay_buffer: REPLAY_BUFFER,
        key_write_buffer: WRITE_BUFFER,
        value_write_buffer: WRITE_BUFFER,
        block_codec_config: (),
        max_repair: NZUsize!(16),
        max_pending_acks: NZUsize!(16),
        strategy: Sequential,
    }
}

async fn seed_standard_state(
    ctx: RuntimeContext,
    consensus: &MockConsensus,
    partition_prefix: &str,
    blocks: u64,
) {
    let page_cache = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    let mut finalizations = StandardCertificates::init(
        ctx.with_label("finalizations_by_height"),
        immutable_archive_config(
            partition_prefix,
            "finalizations-by-height",
            page_cache.clone(),
            (),
        ),
    )
    .await
    .expect("failed to initialize standard finalizations archive");
    let mut finalized_blocks = StandardBlocks::init(
        ctx.with_label("finalized_blocks"),
        immutable_archive_config(partition_prefix, "finalized-blocks", page_cache, ()),
    )
    .await
    .expect("failed to initialize standard finalized blocks archive");
    let mut metadata: Metadata<RuntimeContext, U64, Height> = Metadata::init(
        ctx.with_label("application_metadata"),
        metadata::Config {
            partition: format!("{partition_prefix}-application-metadata"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize application metadata");

    let mut parent = Sha256Digest::EMPTY;
    for height in 1..=blocks {
        let height = Height::new(height);
        let block = BenchBlock::new((), parent, height, height.get());
        let finalization = make_finalization(
            consensus,
            Round::new(Epoch::zero(), View::new(height.get())),
            View::new(height.get() - 1),
            block.digest(),
        );
        BlockStore::put(&mut finalized_blocks, block.clone())
            .await
            .unwrap();
        CertificateStore::put(&mut finalizations, height, block.digest(), finalization)
            .await
            .unwrap();
        parent = block.digest();
    }

    BlockStore::sync(&mut finalized_blocks).await.unwrap();
    CertificateStore::sync(&mut finalizations).await.unwrap();
    metadata
        .put_sync(LATEST_KEY, Height::new(blocks))
        .await
        .unwrap();
}

fn genesis_commitment(config: CodingConfig) -> Commitment {
    Commitment::from((
        Sha256Digest::EMPTY,
        Sha256Digest::EMPTY,
        Sha256Digest::EMPTY,
        config,
    ))
}

async fn seed_coding_state(
    ctx: RuntimeContext,
    consensus: &MockConsensus,
    partition_prefix: &str,
    blocks: u64,
) {
    let page_cache = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    let mut finalizations = CodingCertificates::init(
        ctx.with_label("finalizations_by_height"),
        immutable_archive_config(
            partition_prefix,
            "finalizations-by-height",
            page_cache.clone(),
            (),
        ),
    )
    .await
    .expect("failed to initialize coding finalizations archive");
    let mut finalized_blocks = CodingBlocks::init(
        ctx.with_label("finalized_blocks"),
        immutable_archive_config(partition_prefix, "finalized-blocks", page_cache, ()),
    )
    .await
    .expect("failed to initialize coding finalized blocks archive");
    let mut metadata: Metadata<RuntimeContext, U64, Height> = Metadata::init(
        ctx.with_label("application_metadata"),
        metadata::Config {
            partition: format!("{partition_prefix}-application-metadata"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to initialize application metadata");

    let mut parent_digest = Sha256Digest::EMPTY;
    let mut parent_commitment = genesis_commitment(consensus.coding_config);
    for height in 1..=blocks {
        let height = Height::new(height);
        let round = Round::new(Epoch::zero(), View::new(height.get()));
        let inner = BenchBlock::new(
            SimplexContext {
                round,
                leader: consensus.leader.clone(),
                parent: (View::new(height.get() - 1), parent_commitment),
            },
            parent_digest,
            height,
            height.get(),
        );
        let coded = CodingBlock::new(inner, consensus.coding_config, &Sequential);
        let commitment = coded.commitment();
        let digest = coded.digest();
        let finalization =
            make_finalization(consensus, round, View::new(height.get() - 1), commitment);
        BlockStore::put(&mut finalized_blocks, StoredCodingBlock::new(coded))
            .await
            .unwrap();
        CertificateStore::put(&mut finalizations, height, digest, finalization)
            .await
            .unwrap();
        parent_digest = digest;
        parent_commitment = commitment;
    }

    BlockStore::sync(&mut finalized_blocks).await.unwrap();
    CertificateStore::sync(&mut finalizations).await.unwrap();
    metadata
        .put_sync(LATEST_KEY, Height::new(blocks))
        .await
        .unwrap();
}

async fn measure_standard_restart(
    ctx: RuntimeContext,
    consensus: &MockConsensus,
    partition_prefix: &str,
    blocks: u64,
) -> Duration {
    let page_cache = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    let start = Instant::now();
    let finalizations = StandardCertificates::init(
        ctx.with_label("finalizations_by_height"),
        immutable_archive_config(
            partition_prefix,
            "finalizations-by-height",
            page_cache.clone(),
            (),
        ),
    )
    .await
    .expect("failed to reopen standard finalizations archive");
    let finalized_blocks = StandardBlocks::init(
        ctx.with_label("finalized_blocks"),
        immutable_archive_config(partition_prefix, "finalized-blocks", page_cache.clone(), ()),
    )
    .await
    .expect("failed to reopen standard finalized blocks archive");
    let (actor, mailbox, recovered_height) = Actor::<
        RuntimeContext,
        StandardVariant,
        Provider,
        StandardCertificates,
        StandardBlocks,
        FixedEpocher,
        Sequential,
    >::init(
        ctx,
        finalizations,
        finalized_blocks,
        actor_config(
            partition_prefix,
            page_cache,
            ConstantProvider::new(consensus.verifier.clone()),
        ),
    )
    .await;
    assert_eq!(recovered_height, Height::new(blocks));
    black_box(actor);
    black_box(mailbox);
    start.elapsed()
}

async fn measure_coding_restart(
    ctx: RuntimeContext,
    consensus: &MockConsensus,
    partition_prefix: &str,
    blocks: u64,
) -> Duration {
    let page_cache = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    let start = Instant::now();
    let finalizations = CodingCertificates::init(
        ctx.with_label("finalizations_by_height"),
        immutable_archive_config(
            partition_prefix,
            "finalizations-by-height",
            page_cache.clone(),
            (),
        ),
    )
    .await
    .expect("failed to reopen coding finalizations archive");
    let finalized_blocks = CodingBlocks::init(
        ctx.with_label("finalized_blocks"),
        immutable_archive_config(partition_prefix, "finalized-blocks", page_cache.clone(), ()),
    )
    .await
    .expect("failed to reopen coding finalized blocks archive");
    let (actor, mailbox, recovered_height) = Actor::<
        RuntimeContext,
        CodingVariant,
        Provider,
        CodingCertificates,
        CodingBlocks,
        FixedEpocher,
        Sequential,
    >::init(
        ctx,
        finalizations,
        finalized_blocks,
        actor_config(
            partition_prefix,
            page_cache,
            ConstantProvider::new(consensus.verifier.clone()),
        ),
    )
    .await;
    assert_eq!(recovered_height, Height::new(blocks));
    black_box(actor);
    black_box(mailbox);
    start.elapsed()
}

fn cleanup_storage(cfg: &Config) {
    if let Err(err) = std::fs::remove_dir_all(cfg.storage_directory()) {
        assert_eq!(
            err.kind(),
            ErrorKind::NotFound,
            "failed to clean benchmark storage directory: {err}"
        );
    }
}

fn bench_restart(c: &mut Criterion) {
    let consensus = MockConsensus::new();
    for variant in [Variant::Standard, Variant::Coding] {
        for blocks in BLOCKS {
            let cfg = Config::default();
            let partition_prefix = format!("marshal-bench-{}-{blocks}", variant.name());

            let builder = TokioRunner::new(cfg.clone());
            match variant {
                Variant::Standard => {
                    let consensus = consensus.clone();
                    let partition_prefix = partition_prefix.clone();
                    builder.start(|ctx| async move {
                        seed_standard_state(ctx, &consensus, &partition_prefix, blocks).await;
                    });
                }
                Variant::Coding => {
                    let consensus = consensus.clone();
                    let partition_prefix = partition_prefix.clone();
                    builder.start(|ctx| async move {
                        seed_coding_state(ctx, &consensus, &partition_prefix, blocks).await;
                    });
                }
            }

            let runner = bench_tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/variant={} blocks={blocks}",
                    module_path!(),
                    variant.name()
                ),
                |b| {
                    let consensus = consensus.clone();
                    let partition_prefix = partition_prefix.clone();
                    b.to_async(&runner).iter_custom(move |iters| {
                        let consensus = consensus.clone();
                        let partition_prefix = partition_prefix.clone();
                        async move {
                            let ctx = context::get::<RuntimeContext>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += match variant {
                                    Variant::Standard => {
                                        measure_standard_restart(
                                            ctx.clone(),
                                            &consensus,
                                            &partition_prefix,
                                            blocks,
                                        )
                                        .await
                                    }
                                    Variant::Coding => {
                                        measure_coding_restart(
                                            ctx.clone(),
                                            &consensus,
                                            &partition_prefix,
                                            blocks,
                                        )
                                        .await
                                    }
                                };
                            }
                            total
                        }
                    });
                },
            );

            cleanup_storage(&cfg);
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
