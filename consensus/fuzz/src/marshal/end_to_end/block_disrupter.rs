//! Byzantine block-dissemination faults on the marshal block-gossip channel.
//!
//! In the standard disrupter target the byzantine node (index [`BYZANTINE_IDX`])
//! runs only a simplex [`Disrupter`](crate::disrupter::Disrupter) on the
//! vote/certificate/resolver channels and no marshal stack, so it never emits on
//! the block-gossip channel (id 2). This actor gives it a [`buffered::Engine`] on
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

use super::twins::{B, Ctx, PublicKeyOf, SchemeOf};
use crate::{BYZANTINE_IDX, simplex::Simplex};
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::mocks::harness::TEST_QUOTA,
    simplex::types::{Notarize, Proposal, Vote},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};
use commonware_p2p::{
    Recipients, Sender as _,
    simulated::{Oracle, Sender},
};
use commonware_runtime::{Clock as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::NZUsize;
use std::{sync::Arc, time::Duration};

/// Delay before the byzantine leader disseminates, giving honest engines time to
/// enter the attack view. Well under the marshal engines' one-second leader
/// timeout so the proposal still arrives before they nullify.
const DISSEMINATE_DELAY: Duration = Duration::from_millis(250);

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
    mut vote_sender: Sender<PublicKeyOf<P>, deterministic::Context>,
    genesis: Sha256Digest,
    attack_view: View,
    fault: MarshalBroadcastFault,
) {
    let (broadcast_sender, broadcast_receiver) = oracle
        .control(byzantine.clone())
        .register(2, TEST_QUOTA)
        .await
        .expect("byzantine block-gossip channel registration failed");
    let (engine, mailbox) = commonware_broadcast::buffered::Engine::new(
        context.child("broadcast"),
        commonware_broadcast::buffered::Config {
            public_key: byzantine.clone(),
            mailbox_size: NZUsize!(100),
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let mailbox: commonware_broadcast::buffered::Mailbox<PublicKeyOf<P>, B<P>> = mailbox;
    engine.start((broadcast_sender, broadcast_receiver));

    let honest: Vec<PublicKeyOf<P>> = participants
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != BYZANTINE_IDX)
        .map(|(_, key)| key.clone())
        .collect();

    let round = Round::new(Epoch::zero(), attack_view);
    let parent_view = View::zero();
    let build = move |timestamp: u64| -> B<P> {
        let block_context = Ctx::<P> {
            round,
            leader: byzantine.clone(),
            parent: (parent_view, genesis),
        };
        B::<P>::new::<Sha256>(
            block_context,
            genesis,
            Height::new(attack_view.get()),
            timestamp,
        )
    };

    context.spawn(move |context| async move {
        context.sleep(DISSEMINATE_DELAY).await;

        let announce = |sender: &mut Sender<PublicKeyOf<P>, deterministic::Context>,
                        block: &B<P>,
                        to: Recipients<PublicKeyOf<P>>| {
            let proposal = Proposal::new(round, parent_view, block.digest());
            if let Some(vote) = Notarize::sign(&scheme, proposal) {
                let message = Vote::<SchemeOf<P>, Sha256Digest>::Notarize(vote).encode();
                let _ = sender.send(to, message, true);
            }
        };

        match fault {
            MarshalBroadcastFault::Omit => {
                // Announce the block to every honest replica but never gossip it.
                let block = build(0);
                announce(&mut vote_sender, &block, Recipients::Some(honest.clone()));
            }
            MarshalBroadcastFault::Partition => {
                // Deliver to every honest replica but the last; it backfills.
                let block = build(0);
                let served = if honest.len() > 1 {
                    honest[..honest.len() - 1].to_vec()
                } else {
                    honest.clone()
                };
                mailbox.broadcast_shared(Recipients::Some(served.clone()), Arc::new(block.clone()));
                announce(&mut vote_sender, &block, Recipients::Some(served));
            }
            MarshalBroadcastFault::Equivocate => {
                // Two conflicting blocks (distinct timestamps -> distinct
                // digests) to disjoint honest sets, each with its own proposal.
                let (first, rest) = honest.split_at(1.min(honest.len()));
                let block_a = build(0);
                let block_b = build(1);
                if !first.is_empty() {
                    mailbox.broadcast_shared(
                        Recipients::Some(first.to_vec()),
                        Arc::new(block_a.clone()),
                    );
                    announce(&mut vote_sender, &block_a, Recipients::Some(first.to_vec()));
                }
                if !rest.is_empty() {
                    mailbox.broadcast_shared(
                        Recipients::Some(rest.to_vec()),
                        Arc::new(block_b.clone()),
                    );
                    announce(&mut vote_sender, &block_b, Recipients::Some(rest.to_vec()));
                }
            }
        }
    });
}
