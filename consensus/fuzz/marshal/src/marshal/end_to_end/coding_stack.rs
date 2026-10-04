//! Coding-variant validator and engine setup for the multi-node liveness
//! runner, generic over the consensus scheme.
//!
//! Mirrors the standard stack in `twins::stack`, with two differences
//! the coding variant requires: shard dissemination replaces the buffered
//! broadcast engine on the block channel, and the Simplex automaton/relay is
//! the [`Marshaled`] wrapper (whose consensus payload is a `Commitment` rather
//! than a `Sha256Digest`).

use super::{
    app::{BlockContextRegistry, BuildableBlock, DeliveryReporter},
    twins::{PublicKeyOf, SchemeOf},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, Write};
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    Block, CertifiableAutomaton, CertifiableBlock, Heightable, Relay,
    marshal::{
        Config, Start,
        ancestry::Ancestry,
        coding::{
            Coding, Marshaled, MarshaledConfig, shards,
            types::{CodedBlock, hash_context},
        },
        core::{Actor, DigestFallback, Mailbox},
        mocks::{
            application::Application,
            block::Block as MockBlock,
            harness::{
                BLOCKS_PER_EPOCH, GENESIS_CODING_CONFIG, PAGE_CACHE_SIZE, PAGE_SIZE, TEST_QUOTA,
            },
        },
        resolver::p2p as resolver,
    },
    simplex::{
        Engine, Floor, ForwardPolicy, Plan, SkipBudget, SkipPolicy, config,
        elector::Config as ElectorConfig, scheme::Scheme as SimplexScheme,
        types::Context as SimplexContext,
    },
    types::{Delta, Epoch, FixedEpocher, Height, Round, View, ViewDelta, coding::Commitment},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_cryptography::{
    Digest as _, Digestible, Hasher, Sha256,
    certificate::{ConstantProvider, Verifier as _},
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender, simulated::Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::immutable;
use commonware_utils::{FuzzRng, NZU64, NZUsize};
use rand::RngExt as _;
use std::{fmt, future::Future, num::NonZeroUsize, sync::Arc, time::Duration};

/// Largest block the shard engines accept.
pub(crate) const MAX_BLOCK_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);

/// Largest shard mailbox the harnesses sample.
const MAX_SHARDS_MAILBOX_SIZE: usize = 16;

/// Samples a shard mailbox size. Half of the runs take a size of one or two,
/// which overflows under normal load: the only way into the overflow policy.
pub(crate) fn sample_shards_mailbox_size(rng: &mut FuzzRng) -> NonZeroUsize {
    if rng.random_range(0..2u8) == 0 {
        NZUsize!(rng.random_range(1..=2))
    } else {
        NZUsize!(rng.random_range(1..=MAX_SHARDS_MAILBOX_SIZE))
    }
}

/// Consensus payload for the coding variant: a commitment over the block, its
/// coding root, and its context.
pub type CommitmentOf<P> = Commitment<CodingB<P>, ReedSolomon<Sha256>, Sha256>;

/// Consensus context for the coding variant: the payload is a [`CommitmentOf`].
pub type CodingCtx<P> = SimplexContext<CommitmentOf<P>, PublicKeyOf<P>>;

/// Application block carried by the coding stack.
///
/// A block's context carries the commitment over that same block, so the block
/// type appears inside its own definition. A newtype breaks the cycle a type
/// alias cannot express; every trait it needs forwards to the inner mock block.
pub struct CodingB<P: Simplex>(MockBlock<Sha256Digest, CodingCtx<P>>);

impl<P: Simplex> BuildableBlock for CodingB<P> {
    fn build(context: CodingCtx<P>, parent: Sha256Digest, height: Height, timestamp: u64) -> Self {
        Self(MockBlock::new::<Sha256>(context, parent, height, timestamp))
    }
}

impl<P: Simplex> Clone for CodingB<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: Simplex> fmt::Debug for CodingB<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CodingB").field(&self.0).finish()
    }
}

impl<P: Simplex> PartialEq for CodingB<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P: Simplex> Eq for CodingB<P> {}

impl<P: Simplex> Write for CodingB<P> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<P: Simplex> Read for CodingB<P> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        MockBlock::read_cfg(reader, cfg).map(Self)
    }
}

impl<P: Simplex> EncodeSize for CodingB<P> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<P: Simplex> Digestible for CodingB<P> {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.0.digest()
    }
}

impl<P: Simplex> Heightable for CodingB<P> {
    fn height(&self) -> Height {
        self.0.height()
    }
}

impl<P: Simplex> Block for CodingB<P> {
    fn parent(&self) -> Self::Digest {
        self.0.parent()
    }
}

impl<P: Simplex> CertifiableBlock for CodingB<P> {
    type Context = CodingCtx<P>;

    fn context(&self) -> Self::Context {
        self.0.context()
    }
}

/// Marshal variant for the coding stack.
pub(crate) type CodingVariant<P> = Coding<CodingB<P>, ReedSolomon<Sha256>, Sha256, PublicKeyOf<P>>;

/// Erasure-coded block the marshal actor stores; the raw [`CodingB`] is what
/// marshal delivers to the application sink.
pub(crate) type CodingCoded<P> = CodedBlock<CodingB<P>, ReedSolomon<Sha256>, Sha256>;

/// Shard dissemination mailbox handed to the marshal actor and the engine.
pub(crate) type ShardsMailbox<P> =
    shards::Mailbox<CodingB<P>, ReedSolomon<Sha256>, Sha256, PublicKeyOf<P>>;

pub(crate) type CodingMarshaled<P, A> = Marshaled<
    deterministic::Context,
    A,
    CodingB<P>,
    ReedSolomon<Sha256>,
    Sha256,
    ConstantProvider<SchemeOf<P>, Epoch>,
    Sequential,
    FixedEpocher,
>;

/// One coding validator: the marshal mailbox, the delivery sink, and the shard
/// mailbox the engine needs to disseminate and reconstruct blocks.
pub(crate) struct CodingValidator<P: Simplex> {
    pub(crate) mailbox: Mailbox<SchemeOf<P>, CodingVariant<P>>,
    pub(crate) application: Application<CodingB<P>>,
    pub(crate) shards: ShardsMailbox<P>,
}

/// Builds one coding validator's marshal actor, resolver, and shard engine.
///
/// Mirrors [`super::twins::stack::setup_validator`] except that the block
/// channel carries shards rather than buffered blocks.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn setup_validator_coding<P: Simplex>(
    context: deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    genesis: CodingCoded<P>,
    max_pending_acks: NonZeroUsize,
    pending_ack_invariant_limit: Option<NonZeroUsize>,
    validator_idx: usize,
    stack: Arc<str>,
    shards_mailbox_size: NonZeroUsize,
) -> CodingValidator<P>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let application = Application::<CodingB<P>>::manual_ack();
    let acknowledger = application.clone();
    context.child("acknowledger").spawn(move |_| async move {
        loop {
            acknowledger.acknowledged().await;
        }
    });
    let delivery_reporter = DeliveryReporter::new(
        validator_idx,
        application.clone(),
        pending_ack_invariant_limit,
        stack,
    );
    let config = Config {
        provider: provider.clone(),
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start: Start::Genesis(genesis.into()),
        mailbox_size: NZUsize!(100),
        view_retention: ViewDelta::new(10),
        max_repair: NZUsize!(10),
        max_pending_acks,
        block_codec_config: (),
        partition_prefix: format!("validator-{validator}"),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    };

    let control = oracle.control(validator.clone());
    let backfill = control.register(1, TEST_QUOTA).await.unwrap();
    let resolver = resolver::init(
        context.child("resolver"),
        resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill,
    );

    // Coding disseminates shards on the block channel instead of whole blocks.
    let shard_config: shards::Config<_, _, _, _, _, _> = shards::Config {
        scheme_provider: provider,
        blocker: oracle.control(validator.clone()),
        max_block_size: MAX_BLOCK_SIZE,
        block_codec_cfg: (),
        strategy: Sequential,
        mailbox_size: shards_mailbox_size,
        peer_buffer_size: NZUsize!(64),
        records: NZUsize!(16),
        background_channel_capacity: NZUsize!(1024),
        peer_provider: oracle.manager(),
    };
    let (shard_engine, shard_mailbox) = shards::Engine::new(context.child("shards"), shard_config);
    let network = control.register(2, TEST_QUOTA).await.unwrap();
    shard_engine.start(network);

    let finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
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
            codec_config: SchemeOf::<P>::certificate_codec_config_unbounded(),
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{}-finalized-blocks-metadata", config.partition_prefix),
            freezer_table_partition: format!(
                "{}-finalized-blocks-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalized-blocks-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalized-blocks-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{}-finalized-blocks-ordinal", config.partition_prefix),
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

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    actor.start(delivery_reporter, shard_mailbox.clone(), resolver);

    CodingValidator {
        mailbox,
        application,
        shards: shard_mailbox,
    }
}

pub(crate) fn coding_marshaled<P: Simplex, A>(
    context: &deterministic::Context,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    application: A,
    marshal_mailbox: Mailbox<SchemeOf<P>, CodingVariant<P>>,
    shards: ShardsMailbox<P>,
) -> CodingMarshaled<P, A>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
    A: commonware_consensus::Application<
            deterministic::Context,
            SigningScheme = SchemeOf<P>,
            Context = CodingCtx<P>,
            Block = CodingB<P>,
            Input = (),
        >,
{
    Marshaled::new(
        context.child("marshaled"),
        MarshaledConfig {
            application,
            marshal: marshal_mailbox,
            shards,
            scheme_provider: provider,
            strategy: Sequential,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        },
    )
}

/// Longest wait for a digest subscription to resolve before it is abandoned.
const DIGEST_SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(2);

/// Application wrapper issuing the digest-keyed marshal lookups the coding
/// wrapper never makes itself.
///
/// `Marshaled` keys every lookup by commitment, so the digest index of the
/// shard engine is only reachable through the public mailbox API. Each
/// proposal subscribes to its own digest before marshal can know the block and
/// looks its parent up by digest; each verification looks the candidate up by
/// digest. A lookup that returns a block must return the block asked for.
pub(crate) struct DigestLookups<P: Simplex, A> {
    inner: A,
    /// Marshal mailbox to probe; `None` passes every call straight through.
    mailbox: Option<Mailbox<SchemeOf<P>, CodingVariant<P>>>,
}

impl<P: Simplex, A> DigestLookups<P, A> {
    pub(crate) const fn new(
        inner: A,
        mailbox: Option<Mailbox<SchemeOf<P>, CodingVariant<P>>>,
    ) -> Self {
        Self { inner, mailbox }
    }

    fn subscribe(&self, runtime: &deterministic::Context, digest: Sha256Digest) {
        let Some(mailbox) = &self.mailbox else {
            return;
        };
        let subscription = mailbox.subscribe_by_digest(digest, DigestFallback::Wait);
        runtime
            .child("digest_subscription")
            .spawn(move |runtime| async move {
                select! {
                    result = subscription => {
                        if let Ok(block) = result {
                            assert_eq!(block.digest(), digest, "digest subscription served another block");
                        }
                    },
                    _ = runtime.sleep(DIGEST_SUBSCRIPTION_TIMEOUT) => {},
                }
            });
    }

    fn lookup(&self, digest: Sha256Digest) -> impl Future<Output = ()> + Send + 'static {
        let mailbox = self.mailbox.clone();
        async move {
            let Some(mailbox) = mailbox else {
                return;
            };
            if let Some(block) = mailbox.get_block(&digest).await {
                assert_eq!(
                    block.digest(),
                    digest,
                    "digest lookup returned another block"
                );
            }
        }
    }
}

impl<P: Simplex, A: Clone> Clone for DigestLookups<P, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<P, A> commonware_consensus::Application<deterministic::Context> for DigestLookups<P, A>
where
    P: Simplex,
    A: commonware_consensus::Application<
            deterministic::Context,
            SigningScheme = SchemeOf<P>,
            Context = CodingCtx<P>,
            Block = CodingB<P>,
            Input = (),
        >,
{
    type SigningScheme = SchemeOf<P>;
    type Context = CodingCtx<P>;
    type Block = CodingB<P>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        let runtime = context.0.child("digest_lookups");
        let block = self.inner.propose(context, ancestry, input).await?;
        self.subscribe(&runtime, block.digest());
        self.lookup(block.parent()).await;
        Some(block)
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let runtime = context.0.child("digest_lookups");
        let candidate = ancestry.peek().map(|block| block.digest());
        let verdict = self.inner.verify(context, ancestry).await;
        if let Some(digest) = candidate {
            self.subscribe(&runtime, digest);
            self.lookup(digest).await;
        }
        verdict
    }
}

/// How a Byzantine proposer's block departs from the one its application built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalFault {
    /// Embeds the previous view's context, so the commitment's context digest
    /// does not bind the round it is proposed in.
    StaleContext,
    /// Links to a digest no block has.
    WrongParent,
    /// Skips a height above its parent.
    SkippedHeight,
}

impl ProposalFault {
    /// Decodes bits 6-7 of a stack selector byte; zero selects an honest proposer.
    pub(crate) const fn from_selector(selector: u8) -> Option<Self> {
        match (selector >> 6) & 0b11 {
            1 => Some(Self::StaleContext),
            2 => Some(Self::WrongParent),
            3 => Some(Self::SkippedHeight),
            _ => None,
        }
    }
}

/// Application of a Byzantine identity whose proposals carry a header fault.
///
/// `Marshaled` encodes whatever block the application returns, so the fault
/// reaches the honest verifiers as a well-formed coded block: a stale context
/// fails their proposal check, a wrong parent or a skipped height fails the
/// reconstructed block's validation. Honest applications never wrap.
pub(crate) struct FaultyProposer<P: Simplex, A> {
    inner: A,
    /// `None` proposes exactly what the inner application built.
    fault: Option<ProposalFault>,
    block_contexts: BlockContextRegistry<CodingCtx<P>>,
}

impl<P: Simplex, A> FaultyProposer<P, A> {
    pub(crate) const fn new(
        inner: A,
        fault: Option<ProposalFault>,
        block_contexts: BlockContextRegistry<CodingCtx<P>>,
    ) -> Self {
        Self {
            inner,
            fault,
            block_contexts,
        }
    }
}

impl<P: Simplex, A: Clone> Clone for FaultyProposer<P, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fault: self.fault,
            block_contexts: self.block_contexts.clone(),
        }
    }
}

impl<P, A> commonware_consensus::Application<deterministic::Context> for FaultyProposer<P, A>
where
    P: Simplex,
    A: commonware_consensus::Application<
            deterministic::Context,
            SigningScheme = SchemeOf<P>,
            Context = CodingCtx<P>,
            Block = CodingB<P>,
            Input = (),
        >,
{
    type SigningScheme = SchemeOf<P>;
    type Context = CodingCtx<P>;
    type Block = CodingB<P>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        let consensus_context = context.1.clone();
        let block = self.inner.propose(context, ancestry, input).await?;
        let Some(fault) = self.fault else {
            return Some(block);
        };
        let (block_context, parent, height) = match fault {
            ProposalFault::StaleContext => {
                let round = consensus_context.round;
                let stale = CodingCtx::<P> {
                    round: Round::new(
                        round.epoch(),
                        View::new(round.view().get().saturating_sub(1)),
                    ),
                    leader: consensus_context.leader,
                    parent: consensus_context.parent,
                };
                (stale, block.parent(), block.height())
            }
            ProposalFault::WrongParent => (
                consensus_context,
                Sha256::hash(&[b"coding-wrong-parent", block.parent().as_ref()]),
                block.height(),
            ),
            ProposalFault::SkippedHeight => {
                (consensus_context, block.parent(), block.height().next())
            }
        };
        let block = CodingB::<P>::build(block_context, parent, height, height.get());
        self.block_contexts.record(block.digest(), block.context());
        Some(block)
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        self.inner.verify(context, ancestry).await
    }
}

/// Starts a coding Simplex engine on caller-supplied network channels.
///
/// Twins uses this entry point after splitting the compromised validator's
/// vote, certificate, and resolver channels.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_engine_coding_with_networks<P: Simplex, EC, A, R>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: EC,
    automaton: A,
    relay: R,
    marshal_mailbox: Mailbox<SchemeOf<P>, CodingVariant<P>>,
    genesis_commitment: CommitmentOf<P>,
    forwarding: ForwardPolicy,
    vote: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
    EC: ElectorConfig<SchemeOf<P>>,
    A: CertifiableAutomaton<Context = CodingCtx<P>, Digest = CommitmentOf<P>>,
    R: Relay<Digest = CommitmentOf<P>, PublicKey = PublicKeyOf<P>, Plan = Plan<PublicKeyOf<P>>>,
{
    let engine = Engine::new(
        context.child("engine"),
        config::Config {
            blocker: oracle.control(validator.clone()),
            scheme,
            elector,
            automaton,
            relay,
            reporter: marshal_mailbox,
            partition: format!("engine-{validator}"),
            mailbox_size: NZUsize!(1024),
            epoch: Epoch::zero(),
            floor: Floor::Genesis(genesis_commitment),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip: SkipPolicy::Enabled {
                timeout: Duration::from_secs(11),
                budget: SkipBudget::Participants,
            },
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forward: forwarding,
            track_historical_votes: false,
        },
    );
    engine.start(vote, certificate, resolver);
}

/// Genesis coded block shared by every coding validator and by the consensus
/// floor, so view-1 proposals link to the block marshal already holds.
pub(crate) fn coding_genesis<P: Simplex>(leader: PublicKeyOf<P>) -> CodingCoded<P> {
    let genesis_parent = CommitmentOf::<P>::from((
        Sha256Digest::EMPTY,
        Sha256Digest::EMPTY,
        Sha256Digest::EMPTY,
        GENESIS_CODING_CONFIG,
    ));
    let context = CodingCtx::<P> {
        round: Round::zero(),
        leader,
        parent: (View::zero(), genesis_parent),
    };
    let inner = CodingB::<P>::build(context, Sha256::hash(&[b""]), Height::zero(), 0);
    let commitment = CommitmentOf::<P>::from((
        inner.digest(),
        inner.digest(),
        hash_context::<Sha256, _>(&inner.context()),
        GENESIS_CODING_CONFIG,
    ));
    CodedBlock::new_trusted(inner, commitment)
}
