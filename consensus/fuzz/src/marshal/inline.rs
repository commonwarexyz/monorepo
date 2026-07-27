//! Fuzz driver for the standard inline and deferred marshal wrappers.
//!
//! The split-header invariant is armed only when the candidate, its embedded
//! parent, and an older conflicting parent are all locally available and the
//! application accepts the candidate. A rejection from verifying the
//! conflicting header is proposal-scoped; certification of the same
//! `(round, digest)` models an honest notarization and must therefore recover
//! through the candidate's embedded context.

use super::multi_node::invariants::CertificationAgreementInvariant;
use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_broadcast::Broadcaster as _;
use commonware_consensus::{
    Application as ConsensusApplication, Automaton, Block, CertifiableAutomaton, Heightable, Relay,
    Reporter,
    marshal::{
        Update,
        ancestry::Ancestry,
        mocks::harness::{
            B, BLOCKS_PER_EPOCH, D, K, NAMESPACE, NUM_VALIDATORS, S, StandardHarness, TestHarness,
            V, setup_network_with_participants,
        },
        standard::{Deferred, Inline},
    },
    simplex::{Plan, scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Context},
    types::{Epoch, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{
    Digestible, Hasher as _,
    certificate::{ConstantProvider, mocks::Fixture},
    sha256::Sha256,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize, channel::oneshot};
use futures::StreamExt;
use std::time::Duration;

const NUM_BLOCKS: u64 = 24;
const MIN_EVENTS: usize = 1;
const MAX_EVENTS: usize = 64;
const EVENT_SETTLE: Duration = Duration::from_millis(20);

fn block_idx(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=((NUM_BLOCKS - 1) as u8))
}

fn block_index(idx: u8) -> usize {
    (idx as u64 % NUM_BLOCKS) as usize
}

fn parent_view(height: Height) -> View {
    height
        .previous()
        .map(|h| View::new(h.get()))
        .unwrap_or(View::zero())
}

#[derive(Debug, Clone, Copy)]
pub enum InlineSeed {
    Proposed,
    Verified,
    Certified,
    Variant,
}

impl Arbitrary<'_> for InlineSeed {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=3)? {
            0 => Self::Proposed,
            1 => Self::Verified,
            2 => Self::Certified,
            _ => Self::Variant,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InlineContext {
    Stored,
    Reproposal,
    CrossEpoch,
    WrongParent,
    /// Reuse the block payload under a header naming an older, locally valid
    /// parent. This models proposal-layer equivocation: the payload is honest,
    /// but the header shown to this validator conflicts with the block's
    /// embedded context.
    CertifiedAncestor {
        parent_idx: u8,
    },
}

impl Arbitrary<'_> for InlineContext {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=7)? {
            0 => Self::Stored,
            1 => Self::Reproposal,
            2 => Self::CrossEpoch,
            3 => Self::WrongParent,
            _ => Self::CertifiedAncestor {
                parent_idx: block_idx(u)?,
            },
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InlineEvent {
    Seed {
        block_idx: u8,
        seed: InlineSeed,
    },
    Propose {
        parent_idx: u8,
        await_result: bool,
    },
    Verify {
        block_idx: u8,
        context: InlineContext,
        await_result: bool,
    },
    Certify {
        block_idx: u8,
        await_result: bool,
    },
    Broadcast {
        block_idx: u8,
        forward: bool,
    },
    ReportTip {
        block_idx: u8,
    },
    CloneWrapper,
    Idle,
}

impl Arbitrary<'_> for InlineEvent {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=99)? {
            0..=24 => Self::Seed {
                block_idx: block_idx(u)?,
                seed: InlineSeed::arbitrary(u)?,
            },
            25..=34 => Self::Propose {
                parent_idx: block_idx(u)?,
                await_result: u.arbitrary()?,
            },
            35..=59 => Self::Verify {
                block_idx: block_idx(u)?,
                context: InlineContext::arbitrary(u)?,
                await_result: u.arbitrary()?,
            },
            60..=74 => Self::Certify {
                block_idx: block_idx(u)?,
                await_result: u.arbitrary()?,
            },
            75..=84 => Self::Broadcast {
                block_idx: block_idx(u)?,
                forward: u.arbitrary()?,
            },
            85..=92 => Self::ReportTip {
                block_idx: block_idx(u)?,
            },
            93..=96 => Self::CloneWrapper,
            _ => Self::Idle,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MarshalInlineInput {
    pub raw_bytes: Vec<u8>,
    pub app_propose_idx: Option<u8>,
    pub app_verify_result: bool,
    pub events: Vec<InlineEvent>,
}

impl Arbitrary<'_> for MarshalInlineInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let event_count = u.int_in_range(MIN_EVENTS..=MAX_EVENTS)?;
        let app_propose_idx = if u.arbitrary()? {
            Some(block_idx(u)?)
        } else {
            None
        };
        let app_verify_result = u.arbitrary()?;

        let mut events = Vec::with_capacity(event_count);
        let boundary_idx = (BLOCKS_PER_EPOCH.get() - 2) as u8;
        events.extend([
            // Exercise split-header equivocation before the general event
            // stream. The fields around this sequence remain fuzz-controlled,
            // including the application verdict, runtime byte tape, and all
            // trailing actions.
            InlineEvent::Seed {
                block_idx: 0,
                seed: InlineSeed::Verified,
            },
            InlineEvent::Seed {
                block_idx: 1,
                seed: InlineSeed::Verified,
            },
            InlineEvent::Seed {
                block_idx: 2,
                seed: InlineSeed::Variant,
            },
            InlineEvent::Verify {
                block_idx: 2,
                context: InlineContext::CertifiedAncestor { parent_idx: 0 },
                await_result: true,
            },
            InlineEvent::Certify {
                block_idx: 2,
                await_result: true,
            },
            InlineEvent::Seed {
                block_idx: 0,
                seed: InlineSeed::Verified,
            },
            InlineEvent::Propose {
                parent_idx: 0,
                await_result: true,
            },
            InlineEvent::Verify {
                block_idx: 1,
                context: InlineContext::Stored,
                await_result: true,
            },
            InlineEvent::Certify {
                block_idx: 1,
                await_result: true,
            },
            InlineEvent::Seed {
                block_idx: boundary_idx,
                seed: InlineSeed::Verified,
            },
            InlineEvent::Verify {
                block_idx: boundary_idx,
                context: InlineContext::Reproposal,
                await_result: true,
            },
            InlineEvent::Certify {
                block_idx: boundary_idx,
                await_result: true,
            },
            InlineEvent::Broadcast {
                block_idx: 1,
                forward: true,
            },
            InlineEvent::Broadcast {
                block_idx: 1,
                forward: false,
            },
            InlineEvent::ReportTip { block_idx: 1 },
            InlineEvent::CloneWrapper,
        ]);
        for _ in events.len()..event_count {
            events.push(InlineEvent::arbitrary(u)?);
        }

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self {
            raw_bytes,
            app_propose_idx,
            app_verify_result,
            events,
        })
    }
}

#[derive(Clone)]
struct InlineApp {
    propose_result: Option<B>,
    verify_result: bool,
}

impl InlineApp {
    fn new(propose_result: Option<B>, verify_result: bool) -> Self {
        Self {
            propose_result,
            verify_result,
        }
    }
}

impl ConsensusApplication<deterministic::Context> for InlineApp {
    type SigningScheme = S;
    type Context = Context<D, K>;
    type Block = B;
    type Input = ();

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
    ) -> Option<Self::Block> {
        let _ = ancestry.peek();
        let _ = ancestry.next().await;
        let (_, consensus_context) = context;
        // A proposer commits to accepting its own proposal under this context.
        // When this deliberately faulty mock rejects verification, it must not
        // manufacture a proposal that would make the harness violate the
        // Application contract by construction.
        if !self.verify_result {
            return None;
        }
        let expected_parent = consensus_context.parent.1;
        let expected_height = Height::new(consensus_context.round.view().get());
        match self.propose_result.clone() {
            None => None,
            Some(block)
                if block.parent() == expected_parent && block.height() == expected_height =>
            {
                Some(block)
            }
            Some(_) => Some(StandardHarness::make_test_block(
                expected_parent,
                expected_parent,
                expected_height,
                expected_height.get(),
                NUM_VALIDATORS as u16,
            )),
        }
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let _ = ancestry.peek();
        let _ = ancestry.next().await;
        self.verify_result
    }
}

impl Reporter for InlineApp {
    type Activity = Update<B>;

    fn report(&mut self, _activity: Self::Activity) -> Feedback {
        Feedback::Ok
    }
}

fn make_chain() -> (B, Vec<B>) {
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
    (genesis, blocks)
}

fn context_for(kind: InlineContext, block: &B, canonical: &[B], me: &K) -> Context<D, K> {
    match kind {
        InlineContext::Stored => block.context.clone(),
        InlineContext::Reproposal => Context {
            round: Round::new(Epoch::zero(), View::new(block.height().get() + 1)),
            leader: me.clone(),
            parent: (View::new(block.height().get()), block.digest()),
        },
        InlineContext::CrossEpoch => Context {
            round: Round::new(Epoch::new(1), View::new(block.height().get())),
            leader: me.clone(),
            parent: (parent_view(block.height()), block.parent()),
        },
        InlineContext::WrongParent => Context {
            round: block.context.round,
            leader: me.clone(),
            parent: (
                parent_view(block.height()),
                Sha256::hash(&[&block.height().get().to_be_bytes()]),
            ),
        },
        InlineContext::CertifiedAncestor { parent_idx } => {
            let oldest_parent_height = block.height().get().saturating_sub(2);
            let parent = &canonical[(parent_idx as u64 % oldest_parent_height.max(1)) as usize];
            Context {
                round: block.context.round,
                leader: block.context.leader.clone(),
                parent: (View::new(parent.height().get()), parent.digest()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum WrapperKind {
    Inline,
    Deferred,
}

#[derive(Clone)]
enum Wrapper {
    Inline(Inline<deterministic::Context, S, InlineApp, B, FixedEpocher>),
    Deferred(Deferred<deterministic::Context, S, InlineApp, B, FixedEpocher>),
}

impl Wrapper {
    fn new(
        kind: WrapperKind,
        context: deterministic::Context,
        application: InlineApp,
        marshal: commonware_consensus::marshal::core::Mailbox<
            S,
            commonware_consensus::marshal::standard::Standard<B>,
        >,
    ) -> Self {
        match kind {
            WrapperKind::Inline => Self::Inline(Inline::new(
                context,
                application,
                marshal,
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            )),
            WrapperKind::Deferred => Self::Deferred(Deferred::new(
                context,
                application,
                marshal,
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            )),
        }
    }

    async fn propose(&mut self, context: Context<D, K>) -> oneshot::Receiver<D> {
        match self {
            Self::Inline(wrapper) => wrapper.propose(context).await,
            Self::Deferred(wrapper) => wrapper.propose(context).await,
        }
    }

    async fn verify(&mut self, context: Context<D, K>, digest: D) -> oneshot::Receiver<bool> {
        match self {
            Self::Inline(wrapper) => wrapper.verify(context, digest).await,
            Self::Deferred(wrapper) => wrapper.verify(context, digest).await,
        }
    }

    async fn certify(&mut self, round: Round, digest: D) -> oneshot::Receiver<bool> {
        match self {
            Self::Inline(wrapper) => wrapper.certify(round, digest).await,
            Self::Deferred(wrapper) => wrapper.certify(round, digest).await,
        }
    }

    fn broadcast(&mut self, digest: D, plan: Plan<K>) -> Feedback {
        match self {
            Self::Inline(wrapper) => wrapper.broadcast(digest, plan),
            Self::Deferred(wrapper) => wrapper.broadcast(digest, plan),
        }
    }

    fn report(&mut self, update: Update<B>) -> Feedback {
        match self {
            Self::Inline(wrapper) => wrapper.report(update),
            Self::Deferred(wrapper) => wrapper.report(update),
        }
    }
}

fn fuzz_marshal_standard(input: MarshalInlineInput, kind: WrapperKind) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;

        let me = participants[0].clone();
        let setup = StandardHarness::setup_validator(
            context.child("validator"),
            &mut oracle,
            me.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let marshal = setup.mailbox;
        let buffer = setup.extra;

        let (_genesis, canonical) = make_chain();
        let propose_result = input
            .app_propose_idx
            .map(|idx| canonical[block_index(idx)].clone());
        let app = InlineApp::new(propose_result, input.app_verify_result);
        let mut wrapper = Wrapper::new(kind, context.child("wrapper"), app, marshal.clone());
        let certification_invariant = CertificationAgreementInvariant::new(
            format!("application=inline-app wrapper={kind:?}").into(),
        );
        let mut available = std::collections::HashSet::new();
        let mut poisoned = std::collections::HashSet::new();

        for event in input.events {
            match event {
                InlineEvent::Seed { block_idx, seed } => {
                    let block = canonical[block_index(block_idx)].clone();
                    let round = block.context.round;
                    match seed {
                        InlineSeed::Proposed => {
                            let (ack, rx) = oneshot::channel();
                            let _ = marshal.proposed(round, block, Recipients::All, ack);
                            if let Ok(sync) = rx.await {
                                let _ = sync.await;
                                available.insert(canonical[block_index(block_idx)].digest());
                            }
                        }
                        InlineSeed::Verified => {
                            if marshal.verified(round, block).await {
                                available.insert(canonical[block_index(block_idx)].digest());
                            }
                        }
                        InlineSeed::Certified => {
                            if marshal.certified(round, block).await {
                                available.insert(canonical[block_index(block_idx)].digest());
                            }
                        }
                        InlineSeed::Variant => {
                            if buffer.broadcast(Recipients::All, block).accepted() {
                                available.insert(canonical[block_index(block_idx)].digest());
                            }
                        }
                    }
                }
                InlineEvent::Propose {
                    parent_idx,
                    await_result,
                } => {
                    let parent = &canonical[block_index(parent_idx)];
                    let propose_context = Context {
                        round: Round::new(Epoch::zero(), View::new(parent.height().get() + 1)),
                        leader: me.clone(),
                        parent: (View::new(parent.height().get()), parent.digest()),
                    };
                    let round = propose_context.round;
                    let rx = wrapper.propose(propose_context).await;
                    if await_result {
                        let result = select! {
                            result = rx => result.ok(),
                            _ = context.sleep(EVENT_SETTLE) => None,
                        };
                        if let Some(digest) = result {
                            certification_invariant.record_proposal(0, round, digest);
                            let _ = wrapper.broadcast(digest, Plan::Propose { round });
                            assert!(
                                marshal.get_block(&digest).await.is_some(),
                                "inline proposal is unavailable after relay"
                            );
                            available.insert(digest);
                        }
                    }
                }
                InlineEvent::Verify {
                    block_idx,
                    context: context_kind,
                    await_result,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let digest = block.digest();
                    let verify_context = context_for(context_kind, block, &canonical, &me);
                    let split_header =
                        matches!(context_kind, InlineContext::CertifiedAncestor { .. })
                            && verify_context.round == block.context.round
                            && verify_context.parent != block.context.parent
                            && available.contains(&digest)
                            && available.contains(&verify_context.parent.1)
                            && available.contains(&block.context.parent.1)
                            && input.app_verify_result;
                    let rx = wrapper.verify(verify_context, digest).await;
                    if await_result {
                        let result = select! {
                            result = rx => result.ok(),
                            _ = context.sleep(EVENT_SETTLE) => None,
                        };
                        if result == Some(true) {
                            assert!(
                                marshal.get_block(&digest).await.is_some(),
                                "inline verify accepted a block that marshal cannot serve"
                            );
                        }
                        if split_header && result == Some(false) {
                            poisoned.insert((block.context.round, digest));
                        }
                    }
                }
                InlineEvent::Certify {
                    block_idx,
                    await_result,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let digest = block.digest();
                    let round = block.context.round;
                    let must_recover = poisoned.remove(&(round, digest));
                    let rx = wrapper.certify(round, digest).await;
                    if await_result {
                        let result = select! {
                            result = rx => result.ok(),
                            _ = context.sleep(if must_recover {
                                Duration::from_secs(5)
                            } else {
                                EVENT_SETTLE
                            }) => None,
                        };
                        if let Some(verdict) = result {
                            certification_invariant
                                .check_certify_agreement(0, round, digest, verdict);
                        }
                        if must_recover {
                            assert_eq!(
                                result,
                                Some(true),
                                "certification adopted a rejection scoped only to an \
                                 equivocating proposal header"
                            );
                        }
                        if result == Some(true) {
                            assert!(
                                marshal.get_block(&digest).await.is_some(),
                                "inline certify accepted a block that marshal cannot serve"
                            );
                        }
                    }
                }
                InlineEvent::Broadcast { block_idx, forward } => {
                    let block = &canonical[block_index(block_idx)];
                    let plan = if forward {
                        Plan::Forward {
                            round: block.context.round,
                            recipients: Recipients::Some(vec![me.clone()]),
                        }
                    } else {
                        Plan::Propose {
                            round: block.context.round,
                        }
                    };
                    let _ = wrapper.broadcast(block.digest(), plan);
                }
                InlineEvent::ReportTip { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let _ = wrapper.report(Update::Tip(
                        block.context.round,
                        block.height(),
                        block.digest(),
                    ));
                }
                InlineEvent::CloneWrapper => {
                    let _ = wrapper.clone();
                }
                InlineEvent::Idle => {}
            }
            context.sleep(EVENT_SETTLE).await;
        }
    });
}

pub fn fuzz_marshal_inline(input: MarshalInlineInput) {
    fuzz_marshal_standard(input, WrapperKind::Inline);
}

pub fn fuzz_marshal_deferred(input: MarshalInlineInput) {
    fuzz_marshal_standard(input, WrapperKind::Deferred);
}
