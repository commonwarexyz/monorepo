//! Fuzz driver for the standard inline marshal wrapper.

use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_broadcast::Broadcaster as _;
use commonware_consensus::{
    marshal::{
        ancestry::Ancestry,
        mocks::harness::{
            setup_network_with_participants, StandardHarness, TestHarness, B, BLOCKS_PER_EPOCH, D,
            K, NAMESPACE, NUM_VALIDATORS, S, V,
        },
        standard::Inline,
        Update,
    },
    simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Context, Plan},
    types::{Epoch, FixedEpocher, Height, Round, View},
    Application as ConsensusApplication, Automaton, Block, CertifiableAutomaton, Heightable, Relay,
    Reporter,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider},
    sha256::Sha256,
    Digestible, Hasher as _,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::{FuzzRng, NZUsize};
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
}

impl Arbitrary<'_> for InlineContext {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=3)? {
            0 => Self::Stored,
            1 => Self::Reproposal,
            2 => Self::CrossEpoch,
            _ => Self::WrongParent,
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

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let _ = ancestry.peek();
        let _ = ancestry.next().await;
        let (_, consensus_context) = context;
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

fn context_for(kind: InlineContext, block: &B, me: &K) -> Context<D, K> {
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
                Sha256::hash(&block.height().get().to_be_bytes()),
            ),
        },
    }
}

pub fn fuzz_marshal_inline(input: MarshalInlineInput) {
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
        let mut inline = Inline::new(
            context.child("inline"),
            app,
            marshal.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );

        for event in input.events {
            match event {
                InlineEvent::Seed { block_idx, seed } => {
                    let block = canonical[block_index(block_idx)].clone();
                    let round = block.context.round;
                    match seed {
                        InlineSeed::Proposed => {
                            let _ = marshal.proposed(round, block).await;
                        }
                        InlineSeed::Verified => {
                            let _ = marshal.verified(round, block).await;
                        }
                        InlineSeed::Certified => {
                            let _ = marshal.certified(round, block).await;
                        }
                        InlineSeed::Variant => {
                            let _ = buffer.broadcast(Recipients::All, block);
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
                    let rx = inline.propose(propose_context).await;
                    if await_result {
                        let result = select! {
                            result = rx => result.ok(),
                            _ = context.sleep(EVENT_SETTLE) => None,
                        };
                        if let Some(digest) = result {
                            assert!(
                                marshal.get_block(&digest).await.is_some(),
                                "inline propose returned a digest that marshal cannot serve"
                            );
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
                    let verify_context = context_for(context_kind, block, &me);
                    let rx = inline.verify(verify_context, digest).await;
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
                    }
                }
                InlineEvent::Certify {
                    block_idx,
                    await_result,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let digest = block.digest();
                    let rx = inline.certify(block.context.round, digest).await;
                    if await_result {
                        let result = select! {
                            result = rx => result.ok(),
                            _ = context.sleep(EVENT_SETTLE) => None,
                        };
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
                    let _ = inline.broadcast(block.digest(), plan);
                }
                InlineEvent::ReportTip { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let _ = inline.report(Update::Tip(
                        block.context.round,
                        block.height(),
                        block.digest(),
                    ));
                }
                InlineEvent::CloneWrapper => {
                    let _ = inline.clone();
                }
                InlineEvent::Idle => {}
            }
            context.sleep(EVENT_SETTLE).await;
        }
    });
}
