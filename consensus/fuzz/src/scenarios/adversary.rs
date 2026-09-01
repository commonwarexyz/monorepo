//! Two coordinated disrupters for the adversarial fuzzing mode, on node 0.
//!
//! The Disrupter is a Simplex-layer mutator (vote 3 / certificate 4 / resolver 5)
//! and cannot touch marshal's channels; the dissemination-layer disrupter owns
//! marshal backfill (1) and block broadcast (2). They coexist because node 0 has
//! no marshal (ch1/ch2 are free to register) and because the Simplex disrupter's
//! [`LiveScope`] faults only views ABOVE the attack view, while the dissemination
//! disrupter's leader announce is at the attack view — so their vote-channel
//! emissions never collide.
//!
//! - **Simplex layer (3/4/5)** — [`start_simplex_disrupter`]: the real
//!   [`Disrupter`] with `LiveScope` semantic mutation (mutate the proposal, then
//!   re-sign), scheduled on the live window above the attack view.
//! - **Dissemination layer (2 + 1)** — [`start_dissemination_disrupter`]: as the
//!   attack-view leader, node 0 omits, partitions, or equivocates the block it
//!   gossips (ch2) while signing a matching notarize (ch3), and on ch1 either
//!   withholds, errors, or serves a well-formed quorum notarization over an
//!   unavailable payload paired with a mismatched block (rejected on validation,
//!   never finalizable).

use super::strategy::LiveScope;
use crate::{
    disrupter::Disrupter,
    marshal::end_to_end::twins::{B, Ctx, PublicKeyOf, SchemeOf},
    scenarios::input::{BackfillFault, BlockFault, FaultPlan},
    simplex::Simplex,
    strategy::SmallScope,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::{
        mocks::harness::{QUORUM, TEST_QUOTA},
        resolver::handler::Key as MarshalKey,
    },
    simplex::types::{Notarization, Notarize, Proposal, Vote},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{Oracle, Sender},
};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{Clock as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, iter::NonEmpty};
use std::{sync::Arc, time::Duration};

/// Marshal backfill and block-broadcast channel ids.
const MARSHAL_BACKFILL: u64 = 1;
const MARSHAL_BROADCAST: u64 = 2;
/// Delay before the byzantine leader disseminates, under the honest leader
/// timeout so the proposal still arrives before honest nodes nullify.
const DISSEMINATE_DELAY: Duration = Duration::from_millis(250);
/// Payload the backfill poison forges a notarization over. No node holds a block
/// with this digest, so the certificate can never be certified or finalized.
const UNAVAILABLE_PAYLOAD: Sha256Digest = Sha256Digest([0xEE; 32]);

/// Simplex-layer disrupter on node 0's consensus channels (3/4/5): a live-scoped
/// [`SmallScope`] faulting distinct views in `[first_view, last_view]`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_simplex_disrupter<P: Simplex>(
    context: deterministic::Context,
    scheme: SchemeOf<P>,
    fault_rounds: u64,
    fault_rounds_bound: u64,
    first_view: u64,
    last_view: u64,
    required_containers: u64,
    vote: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) {
    Disrupter::new_with_epoch(
        context,
        scheme,
        LiveScope::new(
            SmallScope {
                fault_rounds,
                fault_rounds_bound,
            },
            first_view,
            last_view,
        ),
        required_containers,
        Epoch::zero(),
    )
    .start(vote, certificate, resolver);
}

/// Dissemination-layer disrupter on node 0's marshal channels (2 + 1).
///
/// `vote_sender` is a clone of node 0's vote-channel (3) sender used for the
/// leader announce; it does not conflict with the Simplex disrupter because the
/// announce is at the attack view, which the Simplex disrupter never faults.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_dissemination_disrupter<P: Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    node: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    schemes: Vec<SchemeOf<P>>,
    participants: Vec<PublicKeyOf<P>>,
    parent_digest: Sha256Digest,
    parent_view: View,
    attack_view: View,
    attack_height: Height,
    vote_sender: Sender<PublicKeyOf<P>, deterministic::Context>,
    plan: FaultPlan,
) {
    let honest: Vec<PublicKeyOf<P>> = participants
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != super::environment::Node::A.idx())
        .map(|(_, key)| key.clone())
        .collect();
    disseminate::<P>(
        context,
        oracle,
        node.clone(),
        scheme,
        honest,
        parent_digest,
        parent_view,
        attack_view,
        attack_height,
        vote_sender,
        plan.block_fault,
    )
    .await;
    serve_backfill::<P>(
        context,
        oracle,
        node,
        schemes,
        parent_digest,
        parent_view,
        attack_height,
        plan.backfill,
    )
    .await;
}

/// Byzantine block-dissemination on channels 2 (block gossip) and 3 (vote).
#[allow(clippy::too_many_arguments)]
async fn disseminate<P: Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    node: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    honest: Vec<PublicKeyOf<P>>,
    parent_digest: Sha256Digest,
    parent_view: View,
    attack_view: View,
    attack_height: Height,
    mut vote_sender: Sender<PublicKeyOf<P>, deterministic::Context>,
    fault: BlockFault,
) {
    let (broadcast_sender, broadcast_receiver) = oracle
        .control(node.clone())
        .register(MARSHAL_BROADCAST, TEST_QUOTA)
        .await
        .expect("byzantine block-gossip channel registration failed");
    let (engine, mailbox) = commonware_broadcast::buffered::Engine::new(
        context.child("broadcast"),
        commonware_broadcast::buffered::Config {
            public_key: node.clone(),
            mailbox_size: NZUsize!(100),
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let mailbox: commonware_broadcast::buffered::Mailbox<PublicKeyOf<P>, B<P>> = mailbox;
    engine.start((broadcast_sender, broadcast_receiver));

    let round = Round::new(Epoch::zero(), attack_view);
    let build = move |timestamp: u64| -> B<P> {
        let block_context = Ctx::<P> {
            round,
            leader: node.clone(),
            parent: (parent_view, parent_digest),
        };
        B::<P>::new::<Sha256>(block_context, parent_digest, attack_height, timestamp)
    };

    context
        .child("disseminate")
        .spawn(move |context| async move {
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
                BlockFault::Omit => {
                    let block = build(0);
                    announce(&mut vote_sender, &block, Recipients::Some(honest.clone()));
                }
                BlockFault::Partition => {
                    // Gossip to every honest node but the last, yet notarize to all,
                    // so the excluded node must certify by round and fetch the block.
                    let block = build(0);
                    let served = if honest.len() > 1 {
                        honest[..honest.len() - 1].to_vec()
                    } else {
                        honest.clone()
                    };
                    mailbox.broadcast_shared(Recipients::Some(served), Arc::new(block.clone()));
                    announce(&mut vote_sender, &block, Recipients::Some(honest.clone()));
                }
                BlockFault::Equivocate => {
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

/// Byzantine marshal-backfill responder on channel 1.
#[allow(clippy::too_many_arguments)]
async fn serve_backfill<P: Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    node: PublicKeyOf<P>,
    schemes: Vec<SchemeOf<P>>,
    parent_digest: Sha256Digest,
    parent_view: View,
    attack_height: Height,
    fault: BackfillFault,
) {
    let leader = node.clone();
    let (mut sender, mut receiver) = oracle
        .control(node)
        .register(MARSHAL_BACKFILL, TEST_QUOTA)
        .await
        .expect("byzantine backfill channel registration failed");
    context.child("serve_backfill").spawn(move |_| async move {
        while let Ok((peer, message)) = receiver.recv().await {
            if fault == BackfillFault::Withhold {
                continue;
            }
            let Ok(request) = ResolverMessage::<MarshalKey<Sha256Digest>>::decode(message) else {
                continue;
            };
            let ResolverPayload::Request(key) = request.payload else {
                continue;
            };
            let payload = match fault {
                BackfillFault::ServeError => ResolverPayload::Error,
                BackfillFault::Poison => match key {
                    // A well-formed notarization needs `parent_view < round`. The
                    // poison uses `parent = parent_view`, so a request at or below
                    // the attack anchor's parent view cannot be answered with a
                    // well-formed certificate; serve an error instead of a
                    // malformed one.
                    MarshalKey::Notarized { round } if round.view() > parent_view => {
                        let proposal = Proposal::new(round, parent_view, UNAVAILABLE_PAYLOAD);
                        let notarizes: Vec<_> = schemes
                            .iter()
                            .take(QUORUM as usize)
                            .filter_map(|scheme| Notarize::sign(scheme, proposal.clone()))
                            .collect();
                        let Some(notarizes) = NonEmpty::try_new(notarizes.iter()) else {
                            continue;
                        };
                        let Ok(notarization) =
                            Notarization::from_notarizes(&schemes[0], notarizes, &Sequential)
                        else {
                            continue;
                        };
                        let context = Ctx::<P> {
                            round,
                            leader: leader.clone(),
                            parent: (parent_view, parent_digest),
                        };
                        let block = B::<P>::new::<Sha256>(
                            context,
                            parent_digest,
                            attack_height,
                            round.view().get(),
                        );
                        ResolverPayload::Response((notarization, block).encode())
                    }
                    _ => ResolverPayload::Error,
                },
                BackfillFault::Withhold => continue,
            };
            let response = ResolverMessage::<MarshalKey<Sha256Digest>> {
                id: request.id,
                payload,
            }
            .encode();
            let _ = sender.send(Recipients::One(peer), response, true);
        }
    });
}
