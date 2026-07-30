//! Block-building automaton for the multi-node end-to-end marshal model.
//!
//! Plays the simplex [`Automaton`](commonware_consensus::Automaton) /
//! [`Relay`](commonware_consensus::Relay) role (via the marshal
//! [`Deferred`](commonware_consensus::marshal::standard::Deferred),
//! [`Inline`](commonware_consensus::marshal::standard::Inline), or
//! [`Marshaled`](commonware_consensus::marshal::coding::Marshaled) wrapper) for
//! an end-to-end engine whose `reporter` is marshal. On `propose` it reads the parent
//! from the supplied ancestry and emits a contiguous child block
//! (`height = parent + 1`) that embeds the consensus context verbatim. `verify`
//! eventually accepts, with an optional per-view delay used to exercise
//! certification timeouts; ancestry, context, and parent-linkage checks are
//! enforced by the wrapper itself.
//!
//! Generic over the context type `C` so the same builder serves both variants:
//! standard uses `Context<Digest, K>`, coding uses `Context<Commitment, K>`.

use super::input::MAX_TWINS_ROUNDS;
use commonware_actor::Feedback;
use commonware_codec::Codec;
use commonware_consensus::{
    Application, Epochable, Heightable, Reporter, Viewable,
    marshal::{
        Update,
        ancestry::Ancestry,
        mocks::{application::Application as SinkApplication, block::Block},
    },
    types::{Height, Round, View},
};
use commonware_cryptography::{
    Digestible, Sha256, certificate::Scheme, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock as _, deterministic};
use commonware_utils::{FuzzRng, sync::Mutex};
use futures::StreamExt;
use rand_core::Rng as _;
use std::{
    collections::HashMap, fmt, marker::PhantomData, num::NonZeroUsize, sync::Arc, time::Duration,
};

#[derive(Clone)]
pub(crate) struct DeliveryReporter<C>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    validator: usize,
    application: SinkApplication<Block<Sha256Digest, C>>,
    tips: Arc<Mutex<Vec<(Round, Height, Sha256Digest)>>>,
    max_pending_acks: Option<NonZeroUsize>,
    stack: Arc<str>,
}

impl<C> DeliveryReporter<C>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(
        validator: usize,
        application: SinkApplication<Block<Sha256Digest, C>>,
        max_pending_acks: Option<NonZeroUsize>,
        stack: Arc<str>,
    ) -> Self {
        Self {
            validator,
            application,
            tips: Arc::new(Mutex::new(Vec::new())),
            max_pending_acks,
            stack,
        }
    }
}

impl<C> Reporter for DeliveryReporter<C>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    type Activity = Update<Block<Sha256Digest, C>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match &activity {
            Update::Tip(round, height, digest) => {
                let mut tips = self.tips.lock();
                if let Some((last_round, last_height, _)) = tips.last() {
                    assert!(
                        height > last_height,
                        "marshal tip height did not increase: node{} previous_height={} \
                         next_height={}; tips={tips:?}; stack={}",
                        self.validator,
                        last_height.get(),
                        height.get(),
                        self.stack,
                    );
                    assert!(
                        round >= last_round,
                        "marshal tip round regressed: node{} previous_round={} \
                         next_round={}; tips={tips:?}; stack={}",
                        self.validator,
                        last_round,
                        round,
                        self.stack,
                    );
                }
                for (delivered_height, delivered_digest) in self.application.delivered() {
                    if delivered_height == *height {
                        assert_eq!(
                            delivered_digest,
                            *digest,
                            "marshal tip disagrees with delivery: node{} height={} \
                             delivered_digest={} tip_digest={}; stack={}",
                            self.validator,
                            height.get(),
                            delivered_digest,
                            digest,
                            self.stack,
                        );
                    }
                }
                tips.push((*round, *height, *digest));
            }
            Update::Block(block, _) => {
                if let Some(max_pending_acks) = self.max_pending_acks {
                    super::invariants::check_pending_acks(
                        self.validator,
                        &self.application,
                        block.height(),
                        max_pending_acks,
                        &self.stack,
                    );
                }
                for (_, tip_height, tip_digest) in &*self.tips.lock() {
                    if *tip_height == block.height() {
                        assert_eq!(
                            *tip_digest,
                            block.digest(),
                            "marshal delivery disagrees with tip: node{} height={} \
                             tip_digest={} delivered_digest={}; stack={}",
                            self.validator,
                            tip_height.get(),
                            tip_digest,
                            block.digest(),
                            self.stack,
                        );
                    }
                }
            }
        }
        self.application.report(activity)
    }
}

/// Out-of-band registry of blocks constructed by the fuzz applications.
pub(crate) struct BlockContextRegistry<C> {
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
    pub(crate) fn record(&self, digest: Sha256Digest, context: C) {
        self.contexts.lock().insert(digest, context);
    }
}

impl<C: Clone> BlockContextRegistry<C> {
    pub(crate) fn get(&self, digest: &Sha256Digest) -> Option<C> {
        self.contexts.lock().get(digest).cloned()
    }
}

/// Honest block-building application, generic over the consensus context type.
pub struct AlwaysAcceptBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    verification_delay: Option<(View, Duration)>,
    block_contexts: Option<BlockContextRegistry<C>>,
    reporter: Option<DeliveryReporter<C>>,
    _marker: PhantomData<fn() -> (C, S)>,
}

impl<C, S> Default for AlwaysAcceptBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            verification_delay: None,
            block_contexts: None,
            reporter: None,
            _marker: PhantomData,
        }
    }
}

impl<C, S> Clone for AlwaysAcceptBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            verification_delay: self.verification_delay,
            block_contexts: self.block_contexts.clone(),
            reporter: self.reporter.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C, S> AlwaysAcceptBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    /// Delay verification at `view`, then return the normal successful verdict.
    pub const fn with_verification_delay(view: View, delay: Duration) -> Self {
        Self {
            verification_delay: Some((view, delay)),
            block_contexts: None,
            reporter: None,
            _marker: PhantomData,
        }
    }

    pub(crate) fn with_block_contexts(mut self, block_contexts: BlockContextRegistry<C>) -> Self {
        self.block_contexts = Some(block_contexts);
        self
    }

    pub(crate) fn with_reporter(mut self, reporter: DeliveryReporter<C>) -> Self {
        self.reporter = Some(reporter);
        self
    }
}

impl<C, S> Application<deterministic::Context> for AlwaysAcceptBlockBuilderApp<C, S>
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

impl<C, S> Reporter for AlwaysAcceptBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
    S: Send + 'static,
{
    type Activity = Update<Block<Sha256Digest, C>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Some(reporter) = &mut self.reporter else {
            return Feedback::Ok;
        };
        reporter.report(activity)
    }
}

const RANDOM_BUCKETS: u8 = 16;
const PROPOSE_NONE_BUCKET: u8 = 0;
const VERIFY_DELAY_BUCKETS: [u8; 2] = [0, 1];
const VERIFY_REJECT_BUCKET: u8 = 2;
const FAULT_BEHAVIOR_VIEWS: usize = MAX_TWINS_ROUNDS as usize + 1;

/// Honest application selected by the final byte of the general Twins input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationChoice {
    AlwaysAccept,
    /// May temporarily omit proposals, delay verification, or reject blocks.
    /// These behaviors are deterministic and shared by all honest validators.
    /// After the fault-injection prefix, proposals and verifications succeed normally.
    Faulty,
}

impl ApplicationChoice {
    pub(crate) const fn from_selector(selector: u8) -> Self {
        match selector % 2 {
            0 => Self::AlwaysAccept,
            _ => Self::Faulty,
        }
    }
}

impl fmt::Display for ApplicationChoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysAccept => formatter.write_str("always-accept"),
            Self::Faulty => formatter.write_str("faulty"),
        }
    }
}

/// Input-derived per-view behavior shared by every faulty honest application.
///
/// The table is generated once from fuzz bytes, then indexed by view rather
/// than call order so honest validators make the same validity decision.
#[derive(Clone, Copy)]
pub(crate) struct FaultyConfig {
    omit_proposal: [bool; FAULT_BEHAVIOR_VIEWS],
    verification: [VerificationBehavior; FAULT_BEHAVIOR_VIEWS],
    fault_injection_through: View,
}

#[derive(Clone, Copy)]
enum VerificationBehavior {
    Delay(Duration),
    Reject,
    Accept,
}

impl FaultyConfig {
    pub(crate) fn new(rng: &mut FuzzRng, fault_injection_through: View) -> Self {
        let mut omit_proposal = [false; FAULT_BEHAVIOR_VIEWS];
        let mut verification = [VerificationBehavior::Accept; FAULT_BEHAVIOR_VIEWS];
        for view in 0..FAULT_BEHAVIOR_VIEWS {
            let mut samples = [0u8; 3];
            rng.fill_bytes(&mut samples);
            let [propose_sample, verify_sample, delay_sample] = samples;
            omit_proposal[view] = propose_sample % RANDOM_BUCKETS == PROPOSE_NONE_BUCKET;
            verification[view] = match verify_sample % RANDOM_BUCKETS {
                bucket if VERIFY_DELAY_BUCKETS.contains(&bucket) => VerificationBehavior::Delay(
                    Duration::from_secs(1 + u64::from(delay_sample % 3)),
                ),
                VERIFY_REJECT_BUCKET => VerificationBehavior::Reject,
                _ => VerificationBehavior::Accept,
            };
        }
        Self {
            omit_proposal,
            verification,
            fault_injection_through,
        }
    }

    fn behavior_index<C: Viewable>(&self, context: &C) -> Option<usize> {
        if context.view() > self.fault_injection_through {
            return None;
        }
        let view = usize::try_from(context.view().get()).expect("view must fit usize");
        assert!(
            view < FAULT_BEHAVIOR_VIEWS,
            "fault-injection view {view} exceeds the configured behavior table"
        );
        Some(view)
    }

    fn omit_proposal<C>(&self, context: &C) -> bool
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        self.behavior_index(context)
            .is_some_and(|view| self.omit_proposal[view])
    }

    fn verification<C>(&self, context: &C) -> VerificationBehavior
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        self.behavior_index(context)
            .map_or(VerificationBehavior::Accept, |view| self.verification[view])
    }

    pub(crate) fn rejects<C>(&self, context: &C) -> bool
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        matches!(self.verification(context), VerificationBehavior::Reject)
    }
}

/// Block-building application that explores transient construction failures,
/// verification latency, and deterministic application rejection.
pub(crate) struct FaultyBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    inner: AlwaysAcceptBlockBuilderApp<C, S>,
    config: FaultyConfig,
}

impl<C, S> FaultyBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(config: FaultyConfig, verification_delay: Option<(View, Duration)>) -> Self {
        let inner = match verification_delay {
            Some((view, delay)) => {
                AlwaysAcceptBlockBuilderApp::with_verification_delay(view, delay)
            }
            None => AlwaysAcceptBlockBuilderApp::default(),
        };
        Self { inner, config }
    }

    pub(crate) fn with_block_contexts(mut self, block_contexts: BlockContextRegistry<C>) -> Self {
        self.inner = self.inner.with_block_contexts(block_contexts);
        self
    }

    pub(crate) fn with_reporter(mut self, reporter: DeliveryReporter<C>) -> Self {
        self.inner = self.inner.with_reporter(reporter);
        self
    }
}

impl<C, S> Clone for FaultyBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
        }
    }
}

impl<C, S> Reporter for FaultyBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
    S: Send + 'static,
{
    type Activity = Update<Block<Sha256Digest, C>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.inner.report(activity)
    }
}

impl<C, S> Application<deterministic::Context> for FaultyBlockBuilderApp<C, S>
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
            VerificationBehavior::Delay(delay) => {
                context.0.sleep(delay).await;
                self.inner.verify(context, ancestry).await
            }
            VerificationBehavior::Reject => false,
            VerificationBehavior::Accept => self.inner.verify(context, ancestry).await,
        }
    }
}

/// Runtime-selected application for the shared general Twins corpus.
pub(crate) enum SelectedBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    AlwaysAccept(AlwaysAcceptBlockBuilderApp<C, S>),
    Faulty(FaultyBlockBuilderApp<C, S>),
}

impl<C, S> SelectedBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(
        choice: ApplicationChoice,
        config: FaultyConfig,
        verification_delay: Option<(View, Duration)>,
    ) -> Self {
        match choice {
            ApplicationChoice::AlwaysAccept => {
                let application = match verification_delay {
                    Some((view, delay)) => {
                        AlwaysAcceptBlockBuilderApp::with_verification_delay(view, delay)
                    }
                    None => AlwaysAcceptBlockBuilderApp::default(),
                };
                Self::AlwaysAccept(application)
            }
            ApplicationChoice::Faulty => {
                Self::Faulty(FaultyBlockBuilderApp::new(config, verification_delay))
            }
        }
    }

    pub(crate) fn with_block_contexts(self, block_contexts: BlockContextRegistry<C>) -> Self {
        match self {
            Self::AlwaysAccept(application) => {
                Self::AlwaysAccept(application.with_block_contexts(block_contexts))
            }
            Self::Faulty(application) => {
                Self::Faulty(application.with_block_contexts(block_contexts))
            }
        }
    }

    pub(crate) fn with_reporter(self, reporter: DeliveryReporter<C>) -> Self {
        match self {
            Self::AlwaysAccept(inner) => Self::AlwaysAccept(inner.with_reporter(reporter)),
            Self::Faulty(inner) => Self::Faulty(inner.with_reporter(reporter)),
        }
    }

    pub(crate) fn rejects(choice: ApplicationChoice, config: FaultyConfig, context: &C) -> bool
    where
        C: Codec<Cfg = ()> + Viewable,
    {
        match choice {
            ApplicationChoice::AlwaysAccept => false,
            ApplicationChoice::Faulty => config.rejects(context),
        }
    }
}

impl<C, S> Clone for SelectedBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        match self {
            Self::AlwaysAccept(application) => Self::AlwaysAccept(application.clone()),
            Self::Faulty(application) => Self::Faulty(application.clone()),
        }
    }
}

impl<C, S> Reporter for SelectedBlockBuilderApp<C, S>
where
    C: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
    S: Send + 'static,
{
    type Activity = Update<Block<Sha256Digest, C>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::AlwaysAccept(application) => application.report(activity),
            Self::Faulty(application) => application.report(activity),
        }
    }
}

impl<C, S> Application<deterministic::Context> for SelectedBlockBuilderApp<C, S>
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
        match self {
            Self::AlwaysAccept(application) => application.propose(context, ancestry, input).await,
            Self::Faulty(application) => application.propose(context, ancestry, input).await,
        }
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        match self {
            Self::AlwaysAccept(application) => application.verify(context, ancestry).await,
            Self::Faulty(application) => application.verify(context, ancestry).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::Epoch;
    use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn reporter() -> DeliveryReporter<()> {
        DeliveryReporter::new(0, SinkApplication::default(), None, "test".into())
    }

    #[test]
    fn matching_tip_and_delivery_are_allowed() {
        let mut reporter = reporter();
        let block = Arc::new(Block::new::<Sha256>((), digest(0), Height::new(1), 1));
        reporter.report(Update::Tip(round(1), Height::new(1), block.digest()));
        let (ack, _waiter) = Exact::handle();
        reporter.report(Update::Block(block, ack));
    }

    #[test]
    #[should_panic(expected = "tip height did not increase")]
    fn tip_heights_must_increase() {
        let mut reporter = reporter();
        reporter.report(Update::Tip(round(1), Height::new(2), digest(1)));
        reporter.report(Update::Tip(round(2), Height::new(1), digest(2)));
    }

    #[test]
    fn equal_tip_rounds_are_allowed() {
        let mut reporter = reporter();
        reporter.report(Update::Tip(round(1), Height::new(1), digest(1)));
        reporter.report(Update::Tip(round(1), Height::new(2), digest(2)));
    }

    #[test]
    #[should_panic(expected = "tip round regressed")]
    fn tip_rounds_must_not_regress() {
        let mut reporter = reporter();
        reporter.report(Update::Tip(round(2), Height::new(1), digest(1)));
        reporter.report(Update::Tip(round(1), Height::new(2), digest(2)));
    }

    #[test]
    #[should_panic(expected = "delivery disagrees with tip")]
    fn tip_and_delivery_must_agree() {
        let mut reporter = reporter();
        reporter.report(Update::Tip(round(1), Height::new(1), digest(1)));
        let block = Arc::new(Block::new::<Sha256>((), digest(0), Height::new(1), 1));
        let (ack, _waiter) = Exact::handle();
        reporter.report(Update::Block(block, ack));
    }

    #[test]
    #[should_panic(expected = "tip disagrees with delivery")]
    fn delivered_block_and_later_tip_must_agree() {
        let mut reporter = reporter();
        let block = Arc::new(Block::new::<Sha256>((), digest(0), Height::new(1), 1));
        let (ack, _waiter) = Exact::handle();
        reporter.report(Update::Block(block, ack));
        reporter.report(Update::Tip(round(1), Height::new(1), digest(1)));
    }
}
