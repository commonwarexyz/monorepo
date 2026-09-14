//! The marshal variants an engine may run, and the type erasure that keeps
//! consensus monomorphized once per variant.
//!
//! A [`Marshal`] fixes what differs between the standard and the coding
//! marshal: the payload votes and certificates name (a block digest, or a
//! coding commitment), how blocks are disseminated (buffered broadcast, or
//! shards), the wrapper that turns the stateful mailbox into the Simplex
//! automaton (`Deferred`, or `Marshaled`), and how the twins split classifies
//! the dissemination channel. The block type is generic over the variant and
//! over nothing else, so every backend and every application share one block
//! type per variant.
//!
//! Simplex, marshal, and the wrapper are generic over the application they
//! drive and the reporter they notify. Left as they are, each database backend
//! and each application would instantiate the whole consensus stack again.
//! [`ErasedApplication`] and [`ErasedReporter`] erase those two types at the
//! boundary between consensus and the stateful actor, so consensus is compiled
//! once per variant and only the stateful actor and the adapter it manages
//! vary with the backend. The erasure adds one boxed future per proposal and
//! verification on the consensus side of the boundary; the stateful actor,
//! which is the system under test, is reached exactly as before.

#[cfg(any(
    test,
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-cert-mock-state-sync",
    feature = "stateful-cert-mock-twins",
    feature = "stateful-cert-mock-twins-coding",
    feature = "stateful-probe"
))]
use super::MAILBOX_SIZE;
use super::{Ctx, Digest, EPOCH_LENGTH, PublicKey, Scheme, app::Block};
use commonware_actor::Feedback;
use commonware_codec::Read;
use commonware_consensus::{
    Application as ConsensusApplication, CertifiableAutomaton, Relay, Reporter,
    marshal::{
        Update,
        ancestry::{Ancestry, BoxedAncestry},
        core::{Buffer, Mailbox as MarshalMailbox, Variant},
    },
    simplex::Plan,
    types::{Epoch, View},
};
use commonware_cryptography::{Digest as DigestTrait, certificate::ConstantProvider};
use commonware_p2p::{
    Sender as SenderTrait,
    simulated::{Oracle, Receiver},
};
use commonware_runtime::deterministic;
use futures::future::BoxFuture;

/// The epoch-scoped scheme provider every marshal wrapper is built with.
pub(super) type Provider = ConstantProvider<Scheme, Epoch>;

/// One marshal variant.
pub(super) trait Marshal: Clone + Send + Sync + 'static {
    /// Label this variant reports under.
    const NAME: &'static str;

    /// What votes and certificates name, and what a block's embedded context
    /// carries as its parent.
    type Payload: DigestTrait;

    /// The marshal variant this payload belongs to.
    type Variant: Variant<ApplicationBlock = Block<Self>, Commitment = Self::Payload>;

    /// The dissemination mailbox the marshal actor reads blocks from.
    type Buffer: Buffer<Self::Variant, PublicKey = PublicKey>;

    /// The wrapper Simplex drives, built over the erased stateful mailbox.
    type Automaton: CertifiableAutomaton<Context = Ctx<Self>, Digest = Self::Payload>
        + Relay<Digest = Self::Payload, PublicKey = PublicKey, Plan = Plan<PublicKey>>;

    /// What one message on the dissemination channel decodes to.
    type Wire: Read;

    /// The payload the genesis block's context names as its parent.
    fn genesis_parent() -> Self::Payload;

    /// The block digest a payload names.
    fn payload_block(payload: &Self::Payload) -> Digest;

    /// The payload consensus starts from.
    fn genesis_payload(genesis: &Block<Self>) -> Self::Payload;

    /// The genesis block as marshal stores it.
    fn stored_genesis(genesis: &Block<Self>) -> <Self::Variant as Variant>::Block;

    /// Start block dissemination on the broadcast channel.
    fn start_dissemination(
        context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        identity: PublicKey,
        provider: Provider,
        channel: (impl SenderTrait<PublicKey = PublicKey>, Receiver<PublicKey>),
    ) -> Self::Buffer;

    /// Wrap the erased stateful mailbox into the Simplex automaton and relay.
    fn automaton(
        context: deterministic::Context,
        application: ErasedApplication<Self>,
        marshal: MarshalMailbox<Scheme, Self::Variant>,
        buffer: Self::Buffer,
        provider: Provider,
    ) -> Self::Automaton;

    /// Codec configuration for decoding dissemination messages off the wire.
    fn wire_cfg() -> <Self::Wire as Read>::Cfg;

    /// The view a dissemination message belongs to, if it names one.
    fn wire_view(wire: &Self::Wire) -> Option<View>;
}

/// The consensus-facing application, erased over the stateful actor's
/// application type.
pub(super) struct ErasedApplication<M: Marshal>(Box<dyn DynApplication<M>>);

impl<M: Marshal> ErasedApplication<M> {
    /// Erase `application`, which is the stateful actor's mailbox.
    pub(super) fn new(
        application: impl ConsensusApplication<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx<M>,
            Block = Block<M>,
            Input = (),
        >,
    ) -> Self {
        Self(Box::new(application))
    }
}

impl<M: Marshal> Clone for ErasedApplication<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl<M: Marshal> ConsensusApplication<deterministic::Context> for ErasedApplication<M> {
    type SigningScheme = Scheme;
    type Context = Ctx<M>;
    type Block = Block<M>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
    ) -> Option<Self::Block> {
        self.0.propose(context, BoxedAncestry::new(ancestry)).await
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        self.0.verify(context, BoxedAncestry::new(ancestry)).await
    }
}

/// Object-safe form of the consensus application.
trait DynApplication<M: Marshal>: Send {
    fn propose(
        &mut self,
        context: (deterministic::Context, Ctx<M>),
        ancestry: BoxedAncestry<Block<M>>,
    ) -> BoxFuture<'static, Option<Block<M>>>;

    fn verify(
        &mut self,
        context: (deterministic::Context, Ctx<M>),
        ancestry: BoxedAncestry<Block<M>>,
    ) -> BoxFuture<'static, bool>;

    fn clone_box(&self) -> Box<dyn DynApplication<M>>;
}

impl<M, A> DynApplication<M> for A
where
    M: Marshal,
    A: ConsensusApplication<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx<M>,
            Block = Block<M>,
            Input = (),
        >,
{
    // Each call runs on its own clone so the future owns everything it
    // touches. The stateful mailbox is a channel handle, so the clone is what
    // consensus would have made anyway.
    fn propose(
        &mut self,
        context: (deterministic::Context, Ctx<M>),
        ancestry: BoxedAncestry<Block<M>>,
    ) -> BoxFuture<'static, Option<Block<M>>> {
        let mut application = self.clone();
        Box::pin(async move { application.propose(context, ancestry, ()).await })
    }

    fn verify(
        &mut self,
        context: (deterministic::Context, Ctx<M>),
        ancestry: BoxedAncestry<Block<M>>,
    ) -> BoxFuture<'static, bool> {
        let mut application = self.clone();
        Box::pin(async move { application.verify(context, ancestry).await })
    }

    fn clone_box(&self) -> Box<dyn DynApplication<M>> {
        Box::new(self.clone())
    }
}

/// The reporter marshal delivers finalized blocks to, erased over the stateful
/// actor's application type.
pub(super) struct ErasedReporter<M: Marshal>(Box<dyn DynReporter<M>>);

impl<M: Marshal> ErasedReporter<M> {
    /// Erase `reporter`, which is the stateful actor's mailbox.
    pub(super) fn new(reporter: impl Reporter<Activity = Update<Block<M>>>) -> Self {
        Self(Box::new(reporter))
    }
}

impl<M: Marshal> Clone for ErasedReporter<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl<M: Marshal> Reporter for ErasedReporter<M> {
    type Activity = Update<Block<M>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.0.report(activity)
    }
}

/// Object-safe form of the reporter.
trait DynReporter<M: Marshal>: Send {
    fn report(&mut self, activity: Update<Block<M>>) -> Feedback;

    fn clone_box(&self) -> Box<dyn DynReporter<M>>;
}

impl<M, R> DynReporter<M> for R
where
    M: Marshal,
    R: Reporter<Activity = Update<Block<M>>>,
{
    fn report(&mut self, activity: Update<Block<M>>) -> Feedback {
        Reporter::report(self, activity)
    }

    fn clone_box(&self) -> Box<dyn DynReporter<M>> {
        Box::new(self.clone())
    }
}

/// The epocher every marshal wrapper is built with: one epoch spans the run.
fn epocher() -> commonware_consensus::types::FixedEpocher {
    commonware_consensus::types::FixedEpocher::new(EPOCH_LENGTH)
}

#[cfg(any(
    test,
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-cert-mock-state-sync",
    feature = "stateful-cert-mock-twins",
    feature = "stateful-probe"
))]
pub(super) use standard::Standard;
#[cfg(any(
    test,
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-cert-mock-state-sync",
    feature = "stateful-cert-mock-twins",
    feature = "stateful-probe"
))]
mod standard {
    //! The standard marshal: whole blocks over buffered broadcast, wrapped by
    //! `Deferred`.

    use super::*;
    use commonware_broadcast::buffered;
    use commonware_consensus::marshal::standard::{Deferred, Standard as StandardVariant};
    use commonware_cryptography::Digestible;
    use std::sync::Arc;

    /// The standard marshal variant.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct Standard;

    impl Marshal for Standard {
        const NAME: &'static str = "standard";
        type Payload = Digest;
        type Variant = StandardVariant<Block<Self>>;
        type Buffer = buffered::Mailbox<PublicKey, Block<Self>>;
        type Automaton = Deferred<
            deterministic::Context,
            Scheme,
            ErasedApplication<Self>,
            Block<Self>,
            commonware_consensus::types::FixedEpocher,
        >;
        type Wire = Block<Self>;

        fn genesis_parent() -> Self::Payload {
            Digest::EMPTY
        }

        fn payload_block(payload: &Self::Payload) -> Digest {
            *payload
        }

        fn genesis_payload(genesis: &Block<Self>) -> Self::Payload {
            genesis.digest()
        }

        fn stored_genesis(genesis: &Block<Self>) -> <Self::Variant as Variant>::Block {
            Arc::new(genesis.clone())
        }

        fn start_dissemination(
            context: deterministic::Context,
            oracle: &Oracle<PublicKey, deterministic::Context>,
            identity: PublicKey,
            _provider: Provider,
            channel: (impl SenderTrait<PublicKey = PublicKey>, Receiver<PublicKey>),
        ) -> Self::Buffer {
            let (engine, buffer) = buffered::Engine::new(
                context,
                buffered::Config {
                    public_key: identity,
                    mailbox_size: MAILBOX_SIZE,
                    deque_size: 10,
                    priority: false,
                    codec_config: (),
                    peer_provider: oracle.manager(),
                },
            );
            engine.start(channel);
            buffer
        }

        fn automaton(
            context: deterministic::Context,
            application: ErasedApplication<Self>,
            marshal: MarshalMailbox<Scheme, Self::Variant>,
            _buffer: Self::Buffer,
            _provider: Provider,
        ) -> Self::Automaton {
            Deferred::new(context, application, marshal, epocher())
        }

        fn wire_cfg() -> <Self::Wire as Read>::Cfg {}

        /// A broadcast payload is a bare block, whose embedded consensus
        /// context names its round.
        fn wire_view(wire: &Self::Wire) -> Option<View> {
            Some(wire.context.round.view())
        }
    }
}

#[cfg(feature = "stateful-cert-mock-twins-coding")]
pub(super) use coding::Coding;
#[cfg(feature = "stateful-cert-mock-twins-coding")]
mod coding {
    //! The coding marshal: erasure-coded shards over the shard engine, wrapped
    //! by `Marshaled`.

    use super::*;
    use commonware_coding::{CodecConfig, ReedSolomon};
    use commonware_consensus::{
        CertifiableBlock,
        marshal::coding::{
            Coding as CodingVariant, Marshaled, MarshaledConfig, shards,
            types::{CodedBlock, Shard, hash_context},
        },
        types::coding::Commitment,
    };
    use commonware_cryptography::{Digestible, Sha256};
    use commonware_parallel::Sequential;
    use commonware_utils::{NZU16, NZUsize};
    use std::sync::Arc;

    /// The coding marshal variant.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct Coding;

    /// The erasure coding scheme every block is disseminated under.
    type Erasure = ReedSolomon<Sha256>;

    /// The commitment votes and certificates name.
    type Payload = Commitment<Block<Coding>, Erasure, Sha256>;

    /// The coding configuration genesis carries. Genesis is never encoded, so
    /// it names the smallest configuration the commitment can express.
    const GENESIS_CODING_CONFIG: commonware_coding::Config = commonware_coding::Config {
        minimum_shards: NZU16!(1),
        extra_shards: NZU16!(1),
    };

    /// Largest shard the shard engine decodes.
    const MAX_SHARD_SIZE: usize = 1024 * 1024;

    impl Marshal for Coding {
        const NAME: &'static str = "coding";
        type Payload = Payload;
        type Variant = CodingVariant<Block<Self>, Erasure, Sha256, PublicKey>;
        type Buffer = shards::Mailbox<Block<Self>, Erasure, Sha256, PublicKey>;
        type Automaton = Marshaled<
            deterministic::Context,
            ErasedApplication<Self>,
            Block<Self>,
            Erasure,
            Sha256,
            Provider,
            Sequential,
            commonware_consensus::types::FixedEpocher,
        >;
        type Wire = Shard<Block<Self>, Erasure, Sha256>;

        fn genesis_parent() -> Self::Payload {
            Payload::from((
                Digest::EMPTY,
                Digest::EMPTY,
                Digest::EMPTY,
                GENESIS_CODING_CONFIG,
            ))
        }

        fn payload_block(payload: &Self::Payload) -> Digest {
            payload.block()
        }

        fn genesis_payload(genesis: &Block<Self>) -> Self::Payload {
            <Self::Variant as Variant>::commitment(&Self::stored_genesis(genesis))
        }

        /// Genesis is trusted rather than encoded, so its commitment names
        /// the block digest in place of a coding root.
        fn stored_genesis(genesis: &Block<Self>) -> <Self::Variant as Variant>::Block {
            let commitment = Payload::from((
                genesis.digest(),
                genesis.digest(),
                hash_context::<Sha256, _>(&genesis.context()),
                GENESIS_CODING_CONFIG,
            ));
            Arc::new(CodedBlock::new_trusted(genesis.clone(), commitment))
        }

        fn start_dissemination(
            context: deterministic::Context,
            oracle: &Oracle<PublicKey, deterministic::Context>,
            identity: PublicKey,
            provider: Provider,
            channel: (impl SenderTrait<PublicKey = PublicKey>, Receiver<PublicKey>),
        ) -> Self::Buffer {
            let (engine, shards) = shards::Engine::new(
                context,
                shards::Config {
                    scheme_provider: provider,
                    blocker: oracle.control(identity),
                    shard_codec_cfg: Self::wire_cfg(),
                    block_codec_cfg: (),
                    strategy: Sequential,
                    mailbox_size: MAILBOX_SIZE,
                    peer_buffer_size: NZUsize!(64),
                    background_channel_capacity: NZUsize!(1024),
                    peer_provider: oracle.manager(),
                },
            );
            engine.start(channel);
            shards
        }

        fn automaton(
            context: deterministic::Context,
            application: ErasedApplication<Self>,
            marshal: MarshalMailbox<Scheme, Self::Variant>,
            buffer: Self::Buffer,
            provider: Provider,
        ) -> Self::Automaton {
            Marshaled::new(
                context,
                MarshaledConfig {
                    application,
                    marshal,
                    shards: buffer,
                    scheme_provider: provider,
                    strategy: Sequential,
                    epocher: epocher(),
                },
            )
        }

        fn wire_cfg() -> <Self::Wire as Read>::Cfg {
            CodecConfig {
                maximum_shard_size: MAX_SHARD_SIZE,
            }
        }

        /// A shard names the commitment it belongs to, which hashes the
        /// context rather than carrying it, so no view can be read off it.
        fn wire_view(_wire: &Self::Wire) -> Option<View> {
            None
        }
    }
}
