//! Byzantine block-dissemination faults on the marshal block-gossip channel.
//!
//! In the standard disrupter target the byzantine node (index [`BYZANTINE_IDX`])
//! runs only a simplex [`Disrupter`](commonware_consensus_fuzz_core::disrupter::Disrupter) on the
//! vote/certificate/resolver channels and no marshal stack, so it never emits on
//! the block-gossip channel (id 2). This actor gives it a
//! [`buffered::Engine`](commonware_broadcast::buffered::Engine) on
//! that channel and, at the first view of the term it is pinned to lead (view 1,
//! whose parent is genesis), acts as a byzantine leader that either delivers
//! different blocks to disjoint replica sets, withholds the block entirely, or
//! delivers it to only a partition. A matching [`Notarize`] (payload equal to
//! the block digest) is sent on the vote channel so honest replicas fetch and
//! act on what they receive.
//!
//! With a stable term (`term_length > 1`) the byzantine leads views
//! `1..=term_length`; it disseminates only at view 1 and stays silent for the
//! rest of its term. Honest nodes nullify the first view they enter (via the
//! per-view leader/certification timeout), and that nullification covers the
//! whole term, advancing them to the next term without entering the remaining
//! views. The fault is confined to the byzantine's own leader views and never
//! touches honest-led traffic.
//! Every block made available to a notarizing quorum is held by at least two
//! honest replicas, so it is backfillable once the network heals at GST and
//! honest liveness is preserved. Only a single vote is ever signed; no full
//! certificate is forged (which would strand a block no honest node holds and
//! stall progress).
//!
//! Under a trusted continuation the node instead attacks once, on the live chain, at
//! the first term it leads after the release (see [Live]).

use super::{
    BLOCKS_PER_EPOCH,
    twins::{B, Ctx, PublicKeyOf, SchemeOf},
};
use arbitrary::Arbitrary;
use commonware_broadcast::{Broadcaster as _, buffered::Mailbox};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Heightable as _,
    marshal::mocks::{block::ready, harness::TEST_QUOTA},
    simplex::types::{Notarize, Proposal, Vote},
    types::{Epoch, Height, Round, TermLength, View},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX,
    byzantine::{self, Counting},
    continuation::{MarkedReceiver, Marker},
    simplex::Simplex,
};
use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};
use commonware_macros::select;
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::NZUsize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Label the matching notarize votes count under.
pub(crate) const ANNOUNCE_ACTOR: &str = "block_announce";
/// Label the block gossip counts under.
pub(crate) const GOSSIP_ACTOR: &str = "block_gossip";
/// Label a gossiped block that claims a forged height counts under.
pub(crate) const FORGED_HEIGHT_ACTOR: &str = "block_forged_height";

/// Delay before the byzantine leader disseminates, giving honest engines time to
/// enter the attack view. Well under the marshal engines' one-second leader
/// timeout so the proposal still arrives before they nullify.
const DISSEMINATE_DELAY: Duration = Duration::from_millis(250);

/// Longest a live attack waits for its parent block, well under the marshal engines'
/// one-second leader timeout.
const PARENT_TIMEOUT: Duration = Duration::from_millis(250);

/// How the byzantine leader disseminates the block it is pinned to propose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarshalBroadcastFault {
    /// Announce the proposal but never disseminate its block: honest replicas
    /// cannot fetch it and nullify the view.
    Omit,
    /// Deliver the block (and proposal) to every honest replica but one; the
    /// excluded replica must backfill it after GST.
    Partition,
    /// Deliver two conflicting blocks to disjoint honest replica sets, each with
    /// its own matching proposal.
    Equivocate,
}

impl MarshalBroadcastFault {
    /// Samples a mode from a dedicated RNG so the runtime schedule RNG (seeded
    /// from the same bytes) is left undisturbed.
    pub(crate) fn sample(rng: &mut commonware_utils::FuzzRng) -> Self {
        use rand::RngExt as _;
        match rng.random_range(0..3u8) {
            0 => Self::Omit,
            1 => Self::Partition,
            _ => Self::Equivocate,
        }
    }
}

/// Height the byzantine leader's block claims above the contiguous child height.
///
/// A nonzero offset forges a height the honest marshal must reject; under a
/// pipelined handoff such a block can be the uncertified parent an incoming
/// leader builds on.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightOffset {
    Zero,
    One,
    Two,
}

impl HeightOffset {
    fn apply(self, height: Height) -> Height {
        let offset = match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Two => 2,
        };
        Height::new(height.get() + offset)
    }
}

/// Where the block-disseminator attacks.
pub(crate) enum Attack<P: Simplex> {
    /// `view`, which the byzantine node leads, on the genesis block `genesis`, at the
    /// height of `view`, after [DISSEMINATE_DELAY].
    Genesis { view: View, genesis: Sha256Digest },
    /// The first view a live cluster offers (see [Live]).
    Live(Live<P>),
}

/// A live attack: the first view above `after` that starts a term of `term_length`
/// views and that `led` gives the byzantine node, once it receives on `votes` an honest
/// notarize or finalize vote for the view before it. The block builds on that vote's
/// block, which the node's own block cache must hold within [PARENT_TIMEOUT] (else the
/// next such view is tried), and goes out at once; there is no attack once its height
/// would leave epoch 0, or once `votes` closes. `attacked` is set when the attack goes out.
pub(crate) struct Live<P: Simplex> {
    pub(crate) votes: Receiver<PublicKeyOf<P>>,
    pub(crate) after: View,
    pub(crate) term_length: TermLength,
    pub(crate) led: Box<dyn Fn(View) -> bool + Send>,
    pub(crate) attacked: Arc<AtomicBool>,
}

/// An attack's round, parent (its view and digest) and height.
type Target = (Round, (View, Sha256Digest), Height);

impl<P: Simplex> Live<P> {
    /// The target of the attack; `None` when there is none.
    async fn target(
        mut self,
        context: &deterministic::Context,
        blocks: &Mailbox<PublicKeyOf<P>, B<P>>,
    ) -> Option<Target> {
        loop {
            let (_, message) = self.votes.recv().await.ok()?;
            let proposal = match Vote::<SchemeOf<P>, Sha256Digest>::decode(message) {
                Ok(Vote::Notarize(vote)) => vote.proposal,
                Ok(Vote::Finalize(vote)) => vote.proposal,
                _ => continue,
            };
            let Some(view) = proposal.round.view().get().checked_add(1).map(View::new) else {
                continue;
            };
            if proposal.round.epoch() != Epoch::zero()
                || view <= self.after
                || !view.is_term_start(self.term_length)
                || !(self.led)(view)
            {
                continue;
            }
            // Each view is tried once.
            self.after = view;
            let parent = select! {
                block = blocks.subscribe(proposal.payload) => block.ok(),
                _ = context.sleep(PARENT_TIMEOUT) => None,
            };
            let Some(parent) = parent else {
                continue;
            };
            // No block above the last height of epoch 0 is accepted.
            if parent.height().get() >= BLOCKS_PER_EPOCH.get() - 1 {
                return None;
            }
            let height = parent.height().next();
            let round = Round::new(Epoch::zero(), view);
            // The caller disseminates the target before it next yields.
            self.attacked.store(true, Ordering::Relaxed);
            return Some((round, (proposal.round.view(), proposal.payload), height));
        }
    }
}

/// Starts the byzantine block-disseminator on channel 2 for `byzantine`.
///
/// `attack_view` must be a view `byzantine` leads whose parent is the genesis
/// block; `genesis` is that genesis block's digest. If `byzantine` is not the
/// elected leader of `attack_view`, honest replicas reject the fabricated
/// proposals (their embedded leader will not match) and the run proceeds as if
/// no block were proposed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start<P: Simplex>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    scheme: SchemeOf<P>,
    byzantine: PublicKeyOf<P>,
    participants: Vec<PublicKeyOf<P>>,
    vote_sender: Sender<PublicKeyOf<P>, deterministic::Context>,
    genesis: Sha256Digest,
    attack_view: View,
    fault: MarshalBroadcastFault,
    height_offset: HeightOffset,
) {
    let broadcast = oracle
        .control(byzantine.clone())
        .register(2, TEST_QUOTA)
        .await
        .expect("byzantine block-gossip channel registration failed");
    // The gossip engine detaches: it stops once the dissemination is done.
    drop(start_with::<P>(
        context,
        oracle,
        scheme,
        byzantine,
        participants,
        vote_sender,
        broadcast,
        None,
        Attack::Genesis {
            view: attack_view,
            genesis,
        },
        fault,
        height_offset,
        false,
    ));
}

/// The block-disseminator of [start] on `byzantine`'s registered `broadcast` channel:
/// it disseminates one block where `attack` says, under `fault`, at the height
/// `height_offset` forges. Returns the gossip
/// engine's task; `marker` is set when that task first polls its receiver. The engine
/// stops once the dissemination is done, or there is none, unless `linger` keeps it
/// running, sending nothing more, for the rest of the run.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_with<P: Simplex>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    scheme: SchemeOf<P>,
    byzantine: PublicKeyOf<P>,
    participants: Vec<PublicKeyOf<P>>,
    vote_sender: Sender<PublicKeyOf<P>, deterministic::Context>,
    (broadcast_sender, broadcast_receiver): (
        Sender<PublicKeyOf<P>, deterministic::Context>,
        Receiver<PublicKeyOf<P>>,
    ),
    marker: Option<Marker>,
    attack: Attack<P>,
    fault: MarshalBroadcastFault,
    height_offset: HeightOffset,
    linger: bool,
) -> Handle<()> {
    let mut vote_sender = Counting::new(vote_sender, ANNOUNCE_ACTOR);
    let (engine, mailbox) = commonware_broadcast::buffered::Engine::new(
        context.child("broadcast"),
        commonware_broadcast::buffered::Config {
            public_key: byzantine.clone(),
            mailbox_size: NZUsize!(100),
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
            strategy: Sequential,
        },
    );
    let mailbox: Mailbox<PublicKeyOf<P>, B<P>> = mailbox;
    let gossip = engine.start((
        Counting::new(broadcast_sender, GOSSIP_ACTOR),
        MarkedReceiver::new(broadcast_receiver, marker),
    ));

    let honest: Vec<PublicKeyOf<P>> = participants
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != BYZANTINE_IDX)
        .map(|(_, key)| key.clone())
        .collect();

    // The gossip engine was spawned under this context, so the disseminating
    // task must run from a sibling: a task's exit aborts the supervision
    // subtree of the context it was spawned from.
    context
        .child("disseminate")
        .spawn(move |context| async move {
            let target = match attack {
                Attack::Genesis { view, genesis } => {
                    context.sleep(DISSEMINATE_DELAY).await;
                    let round = Round::new(Epoch::zero(), view);
                    Some((round, (View::zero(), genesis), Height::new(view.get())))
                }
                Attack::Live(live) => live.target(&context, &mailbox).await,
            };
            if let Some(target) = target {
                disseminate::<P>(
                    &scheme,
                    byzantine,
                    &honest,
                    &mut vote_sender,
                    &mailbox,
                    target,
                    fault,
                    height_offset,
                );
            }
            if linger {
                // The engine runs while its mailbox lives.
                std::future::pending::<()>().await;
            }
        });
    gossip
}

/// Disseminates the block `target` describes, as `byzantine` to the `honest`
/// replicas, under `fault`, at the height `height_offset` forges.
#[allow(clippy::too_many_arguments)]
fn disseminate<P: Simplex>(
    scheme: &SchemeOf<P>,
    byzantine: PublicKeyOf<P>,
    honest: &[PublicKeyOf<P>],
    vote_sender: &mut Counting<Sender<PublicKeyOf<P>, deterministic::Context>>,
    mailbox: &Mailbox<PublicKeyOf<P>, B<P>>,
    (round, (parent_view, parent), height): Target,
    fault: MarshalBroadcastFault,
    height_offset: HeightOffset,
) {
    let height = height_offset.apply(height);
    let forged = || {
        if height_offset != HeightOffset::Zero {
            byzantine::record(FORGED_HEIGHT_ACTOR);
        }
    };
    let build = move |timestamp: u64| -> B<P> {
        let block_context = Ctx::<P> {
            round,
            leader: byzantine.clone(),
            parent: (parent_view, parent),
        };
        B::<P>::new::<Sha256>(block_context, parent, height, timestamp)
    };
    let announce = |sender: &mut Counting<Sender<PublicKeyOf<P>, deterministic::Context>>,
                    block: &B<P>,
                    to: Recipients<PublicKeyOf<P>>| {
        let proposal = Proposal::new(round, parent_view, block.digest());
        if let Some(vote) = Notarize::sign(scheme, proposal) {
            let message = Vote::<SchemeOf<P>, Sha256Digest>::Notarize(vote).encode();
            let _ = sender.send(to, message, true);
        }
    };

    match fault {
        MarshalBroadcastFault::Omit => {
            // Announce the block to every honest replica but never gossip it.
            let block = build(0);
            announce(vote_sender, &block, Recipients::Some(honest.to_vec()));
        }
        MarshalBroadcastFault::Partition => {
            // Deliver to every honest replica but the last; it backfills.
            let block = build(0);
            let served = if honest.len() > 1 {
                honest[..honest.len() - 1].to_vec()
            } else {
                honest.to_vec()
            };
            mailbox.broadcast(Recipients::Some(served.clone()), ready(block.clone()));
            forged();
            announce(vote_sender, &block, Recipients::Some(served));
        }
        MarshalBroadcastFault::Equivocate => {
            // Two conflicting blocks (distinct timestamps -> distinct
            // digests) to disjoint honest sets, each with its own proposal.
            let (first, rest) = honest.split_at(1.min(honest.len()));
            let block_a = build(0);
            let block_b = build(1);
            if !first.is_empty() {
                mailbox.broadcast(Recipients::Some(first.to_vec()), ready(block_a.clone()));
                forged();
                announce(vote_sender, &block_a, Recipients::Some(first.to_vec()));
            }
            if !rest.is_empty() {
                mailbox.broadcast(Recipients::Some(rest.to_vec()), ready(block_b.clone()));
                forged();
                announce(vote_sender, &block_b, Recipients::Some(rest.to_vec()));
            }
        }
    }
}
