//! Block-building automaton for the multi-node marshal liveness model.
//!
//! Plays the simplex [`Automaton`](commonware_consensus::Automaton) /
//! [`Relay`](commonware_consensus::Relay) role (via the marshal
//! [`Deferred`](commonware_consensus::marshal::standard::Deferred) or
//! [`Marshaled`](commonware_consensus::marshal::coding::Marshaled) wrapper) for
//! a live engine whose `reporter` is marshal. On `propose` it reads the parent
//! from the supplied ancestry and emits a contiguous child block
//! (`height = parent + 1`) that embeds the consensus context verbatim. `verify`
//! eventually accepts, with an optional per-view delay used to exercise
//! certification timeouts; ancestry, context, and parent-linkage checks are
//! enforced by the wrapper itself.
//!
//! Generic over the context type `C` so the same builder serves both variants:
//! standard uses `Context<Digest, K>`, coding uses `Context<Commitment, K>`.

use commonware_codec::Codec;
use commonware_consensus::{
    Application, Epochable, Heightable, Viewable,
    marshal::{
        ancestry::Ancestry,
        mocks::{block::Block, harness::S as DefaultSigningScheme},
    },
    types::View,
};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, certificate::Scheme, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock as _, deterministic};
use commonware_utils::sync::Mutex;
use futures::StreamExt;
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

/// Out-of-band registry of blocks constructed by the fuzz applications.
pub(super) struct BlockContextRegistry<C> {
    contexts: Arc<Mutex<HashMap<Sha256Digest, C>>>,
}

impl<C> Default for BlockContextRegistry<C> {
    fn default() -> Self {
        Self {
            contexts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<C> Clone for BlockContextRegistry<C> {
    fn clone(&self) -> Self {
        Self {
            contexts: self.contexts.clone(),
        }
    }
}

impl<C> BlockContextRegistry<C> {
    pub(super) fn record(&self, digest: Sha256Digest, context: C) {
        self.contexts.lock().insert(digest, context);
    }
}

impl<C: Clone> BlockContextRegistry<C> {
    pub(super) fn get(&self, digest: &Sha256Digest) -> Option<C> {
        self.contexts.lock().get(digest).cloned()
    }
}

/// Honest block-building application, generic over the consensus context type.
pub struct BlockBuilderApp<C, S = DefaultSigningScheme> {
    verification_delay: Option<(View, Duration)>,
    block_contexts: Option<BlockContextRegistry<C>>,
    _marker: PhantomData<fn() -> (C, S)>,
}

impl<C, S> Default for BlockBuilderApp<C, S> {
    fn default() -> Self {
        Self {
            verification_delay: None,
            block_contexts: None,
            _marker: PhantomData,
        }
    }
}

impl<C, S> Clone for BlockBuilderApp<C, S> {
    fn clone(&self) -> Self {
        Self {
            verification_delay: self.verification_delay,
            block_contexts: self.block_contexts.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C, S> BlockBuilderApp<C, S> {
    /// Delay verification at `view`, then return the normal successful verdict.
    pub const fn with_verification_delay(view: View, delay: Duration) -> Self {
        Self {
            verification_delay: Some((view, delay)),
            block_contexts: None,
            _marker: PhantomData,
        }
    }

    pub(super) fn with_block_contexts(mut self, block_contexts: BlockContextRegistry<C>) -> Self {
        self.block_contexts = Some(block_contexts);
        self
    }
}

impl<C, S> Application<deterministic::Context> for BlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Epochable + Viewable + Clone + PartialEq + Send + Sync + 'static,
    S: Scheme,
{
    type SigningScheme = S;
    type Context = C;
    type Block = Block<Sha256Digest, C>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
    ) -> Option<Self::Block> {
        let (_, consensus_context) = context;
        // The first ancestor is the parent (highest height); the wrapper seeds
        // the stream with the parent it already fetched for this round.
        let parent = ancestry.next().await?;
        let height = parent.height().next();
        let block = Block::<Sha256Digest, C>::new::<Sha256>(
            consensus_context,
            parent.digest(),
            height,
            height.get(),
        );
        if let Some(block_contexts) = &self.block_contexts {
            block_contexts.record(block.digest(), block.context.clone());
        }
        Some(block)
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let (runtime, consensus) = context;
        if let Some((view, delay)) = self.verification_delay
            && consensus.view() == view
        {
            runtime.sleep(delay).await;
        }
        true
    }
}

const RANDOM_BUCKETS: u8 = 16;
const PROPOSE_NONE_BUCKET: u8 = 0;
const VERIFY_DELAY_BUCKETS: [u8; 2] = [0, 1];
const VERIFY_REJECT_BUCKET: u8 = 2;

/// Input-derived behavior shared by every randomized honest application.
///
/// Outcomes are keyed by consensus context rather than call order so honest
/// validators make the same validity decision for the same proposal.
#[derive(Clone, Copy)]
pub(super) struct RandomizedConfig {
    seed: u64,
    randomized_through: View,
}

enum VerificationBehavior {
    Delay(Duration),
    Reject,
    Accept,
}

impl RandomizedConfig {
    pub(super) const fn new(seed: u64, randomized_through: View) -> Self {
        Self {
            seed,
            randomized_through,
        }
    }

    fn sample<C: Codec<Cfg = ()>>(&self, domain: &[u8], context: &C) -> Sha256Digest {
        Sha256::hash(&[domain, &self.seed.to_be_bytes(), &context.encode()])
    }

    fn enabled<C: Viewable>(&self, context: &C) -> bool {
        context.view() <= self.randomized_through
    }

    fn omit_proposal<C>(&self, context: &C) -> bool
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        if !self.enabled(context) {
            return false;
        }
        let sample = self.sample(b"marshal-fuzz-propose", context);
        sample.as_ref()[0] % RANDOM_BUCKETS == PROPOSE_NONE_BUCKET
    }

    fn verification<C>(&self, context: &C) -> VerificationBehavior
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        if !self.enabled(context) {
            return VerificationBehavior::Accept;
        }
        let sample = self.sample(b"marshal-fuzz-verify", context);
        let bytes: &[u8] = sample.as_ref();
        match bytes[0] % RANDOM_BUCKETS {
            bucket if VERIFY_DELAY_BUCKETS.contains(&bucket) => {
                VerificationBehavior::Delay(Duration::from_secs(1 + u64::from(bytes[1] % 3)))
            }
            VERIFY_REJECT_BUCKET => VerificationBehavior::Reject,
            _ => VerificationBehavior::Accept,
        }
    }

    pub(super) fn rejects<C>(&self, context: &C) -> bool
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        matches!(self.verification(context), VerificationBehavior::Reject)
    }
}

/// Block-building application that explores transient construction failures,
/// verification latency, and deterministic application rejection.
pub(super) struct RandomizedBlockBuilderApp<C, S = DefaultSigningScheme> {
    inner: BlockBuilderApp<C, S>,
    config: RandomizedConfig,
}

impl<C, S> RandomizedBlockBuilderApp<C, S> {
    pub(super) fn new(
        config: RandomizedConfig,
        verification_delay: Option<(View, Duration)>,
    ) -> Self {
        let inner = match verification_delay {
            Some((view, delay)) => BlockBuilderApp::with_verification_delay(view, delay),
            None => BlockBuilderApp::default(),
        };
        Self { inner, config }
    }

    pub(super) fn with_block_contexts(mut self, block_contexts: BlockContextRegistry<C>) -> Self {
        self.inner = self.inner.with_block_contexts(block_contexts);
        self
    }
}

impl<C, S> Clone for RandomizedBlockBuilderApp<C, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
        }
    }
}

impl<C, S> Application<deterministic::Context> for RandomizedBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Epochable + Viewable + Clone + PartialEq + Send + Sync + 'static,
    S: Scheme,
{
    type SigningScheme = S;
    type Context = C;
    type Block = Block<Sha256Digest, C>;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        // A proposer commits to verifying its own block, so skip contexts this
        // application would permanently reject.
        if self.config.rejects(&context.1) || self.config.omit_proposal(&context.1) {
            return None;
        }
        self.inner.propose(context, ancestry, input).await
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        match self.config.verification(&context.1) {
            VerificationBehavior::Delay(delay) => context.0.sleep(delay).await,
            VerificationBehavior::Reject => return false,
            VerificationBehavior::Accept => {}
        }
        self.inner.verify(context, ancestry).await
    }
}
