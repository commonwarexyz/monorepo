//! Commitment-typed Byzantine actor for coding end-to-end targets.
//!
//! Besides equivocating on the consensus channels, the actor can disrupt shard
//! dissemination (re-sending mutations of the honest shards it observes and
//! proposing coded blocks whose commitment does not describe their bytes) and
//! poison block backfill (answering block requests with coded blocks that
//! decode but mismatch the requested commitment). Every fault is sampled from
//! the fuzz tape, and each one is attributable to the Byzantine identity alone.

use super::{
    app::BuildableBlock as _,
    coding_stack::{CodingB, CodingCoded, CodingCtx, CommitmentOf, MAX_BLOCK_SIZE},
    twins::{PublicKeyOf, SchemeOf},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, FixedSize as _, Write as _};
use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as CodingScheme};
use commonware_consensus::{
    CertifiableBlock as _, Viewable,
    marshal::{
        coding::types::{Shard, coding_config_for_participants, hash_context},
        mocks::harness::{GENESIS_CODING_CONFIG, QUORUM},
        resolver::handler::Key,
    },
    simplex::{
        scheme::Scheme as SimplexScheme,
        types::{Finalize, Notarization, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Height, Round, View},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX,
    simplex::Simplex,
    strategy::{AnyScope, FutureScope, SmallScope, Strategy as _, StrategyChoice},
};
use commonware_cryptography::{
    Committable as _, Digest, Digestible as _, Hasher as _, Sha256, certificate::Scheme as _,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::{Receiver, Recipients, Sender, simulated};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, non_empty};
use rand::RngExt as _;
use rand_core::Rng as _;
use std::collections::{BTreeMap, HashSet};

/// Shard wire type of the coding stack.
type ShardOf<P> = Shard<CodingB<P>, ReedSolomon<Sha256>, Sha256>;

/// A marshal channel registered for the Byzantine identity.
pub(crate) type MarshalNetwork<P> = (
    simulated::Sender<PublicKeyOf<P>, deterministic::Context>,
    simulated::Receiver<PublicKeyOf<P>>,
);

/// Whether the Byzantine identity leads a view.
pub(crate) type Leads = Box<dyn Fn(View) -> bool + Send>;

/// Byzantine behaviour beyond consensus-channel equivocation.
pub(crate) struct CodingFaults<P: Simplex> {
    /// Shard channel of the Byzantine identity and the views it leads.
    pub(crate) shards: Option<(MarshalNetwork<P>, Leads)>,
    /// Samples every fault decision.
    pub(crate) rng: FuzzRng,
}

impl<P: Simplex> CodingFaults<P> {
    /// Consensus-channel equivocation only.
    pub(crate) fn none() -> Self {
        Self {
            shards: None,
            rng: FuzzRng::new(Vec::new()),
        }
    }
}

/// Coded block served for a block backfill request.
#[derive(Clone, Copy, Debug)]
enum BackfillPoison {
    /// Another block under the requested coding config.
    WrongBlock,
    /// The requested digest under another coding config.
    WrongConfig,
    /// Another block whose wire digest claims the requested one, so only the
    /// recomputed commitment or coding root exposes it.
    ForgedDigest,
}

impl BackfillPoison {
    fn sample(rng: &mut FuzzRng) -> Self {
        match rng.random_range(0..3u8) {
            0 => Self::WrongBlock,
            1 => Self::WrongConfig,
            _ => Self::ForgedDigest,
        }
    }
}

/// Mutation of an observed honest shard, re-sent under the Byzantine identity.
#[derive(Clone, Copy, Debug)]
enum ShardFault {
    /// The shard as received: honest gossip of the actor's own index, or a
    /// shard the actor does not own.
    Replay,
    /// The actor's own index carrying another index's bytes; batch
    /// verification rejects it.
    Invalid,
    /// Each peer's assigned index carrying these bytes; eager verification
    /// rejects it when it arrives before the leader's shard.
    Assigned,
    /// Two different payloads for the actor's own index.
    Equivocate,
    /// The same payload for the actor's own index twice.
    Duplicate,
    /// A commitment no node proposed, which peers can only buffer.
    Unknown,
    /// Bytes that do not decode as a shard.
    Garbage,
}

impl ShardFault {
    fn sample(rng: &mut FuzzRng) -> Option<Self> {
        Some(match rng.random_range(0..10u8) {
            0..=2 => return None,
            3 => Self::Replay,
            4 => Self::Invalid,
            5 => Self::Assigned,
            6 => Self::Equivocate,
            7 => Self::Duplicate,
            8 => Self::Unknown,
            _ => Self::Garbage,
        })
    }
}

/// Coded block a Byzantine leader proposes: well-formed shards under a real
/// coding root, with a commitment that does not describe the decoded bytes.
#[derive(Clone, Copy, Debug)]
enum LeaderFault {
    /// The commitment names another block digest.
    DigestMismatch,
    /// The coded bytes end in a coding config other than the commitment's.
    ConfigMismatch,
}

impl LeaderFault {
    fn sample(rng: &mut FuzzRng) -> Option<Self> {
        match rng.random_range(0..3u8) {
            0 => None,
            1 => Some(Self::DigestMismatch),
            _ => Some(Self::ConfigMismatch),
        }
    }
}

fn fault_views(
    strategy: StrategyChoice,
    required_containers: u64,
    context: &mut deterministic::Context,
) -> Option<Vec<View>> {
    match strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => SmallScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .disrupter_faults(required_containers, context),
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => FutureScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .disrupter_faults(required_containers, context),
        StrategyChoice::AnyScope
        | StrategyChoice::HeaderScope { .. }
        | StrategyChoice::SplitHeader { .. } => {
            AnyScope.disrupter_faults(required_containers, context)
        }
    }
}

fn conflicting_proposal<P: Simplex>(
    proposal: &Proposal<CommitmentOf<P>>,
) -> Proposal<CommitmentOf<P>> {
    let payload = proposal.payload;
    let block: Sha256Digest = payload.block();
    let conflicting_block = Sha256::hash(&[b"coding-twin", block.as_ref()]);
    let payload = CommitmentOf::<P>::from((
        conflicting_block,
        payload.root(),
        payload.context(),
        payload.config(),
    ));
    Proposal::new(proposal.round, proposal.parent, payload)
}

fn send_notarize<P: Simplex>(
    scheme: &SchemeOf<P>,
    sender: &mut impl Sender<PublicKey = PublicKeyOf<P>>,
    proposal: Proposal<CommitmentOf<P>>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let Some(vote) = Notarize::sign(scheme, proposal) else {
        return;
    };
    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Notarize(vote).encode();
    let _ = sender.send(Recipients::All, message, true);
}

fn send_finalize<P: Simplex>(
    scheme: &SchemeOf<P>,
    sender: &mut impl Sender<PublicKey = PublicKeyOf<P>>,
    proposal: Proposal<CommitmentOf<P>>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let Some(vote) = Finalize::sign(scheme, proposal) else {
        return;
    };
    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Finalize(vote).encode();
    let _ = sender.send(Recipients::All, message, true);
}

async fn drain<P: Simplex>(mut receiver: impl Receiver<PublicKey = PublicKeyOf<P>>) {
    while receiver.recv().await.is_ok() {}
}

/// Participant index of the Byzantine identity, as shards are indexed.
fn own_index<P: Simplex>(scheme: &SchemeOf<P>) -> u16 {
    scheme
        .me()
        .expect("the Byzantine identity is a participant")
        .get()
        .try_into()
        .expect("participant index fits a shard index")
}

/// Public key of the Byzantine identity.
fn own_key<P: Simplex>(scheme: &SchemeOf<P>) -> PublicKeyOf<P> {
    scheme
        .participants()
        .get(own_index::<P>(scheme) as usize)
        .expect("the Byzantine identity is a participant")
        .clone()
}

/// A commitment no node proposed, sharing everything but the block digest.
fn unknown_commitment<P: Simplex>(commitment: &CommitmentOf<P>) -> CommitmentOf<P> {
    let block: Sha256Digest = commitment.block();
    CommitmentOf::<P>::from((
        Sha256::hash(&[b"coding-unknown-commitment", block.as_ref()]),
        commitment.root(),
        commitment.context(),
        commitment.config(),
    ))
}

/// Re-sends mutations of the honest shards the Byzantine identity observes.
///
/// Each observed shard is replayed under a fault sampled from the tape. Honest
/// peers verify every shard against the commitment root, so a mutation is at
/// worst blocked and never reconstructs into a block.
async fn disrupt_shards<P: Simplex>(
    scheme: SchemeOf<P>,
    mut sender: simulated::Sender<PublicKeyOf<P>, deterministic::Context>,
    mut receiver: simulated::Receiver<PublicKeyOf<P>>,
    mut rng: FuzzRng,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let me = own_index::<P>(&scheme);
    let mut seen: BTreeMap<CommitmentOf<P>, Vec<<ReedSolomon<Sha256> as CodingScheme>::Shard>> =
        BTreeMap::new();
    while let Ok((_, bytes)) = receiver.recv().await {
        let Ok(shard) = ShardOf::<P>::decode_cfg(bytes.clone(), &MAX_BLOCK_SIZE) else {
            continue;
        };
        let commitment = shard.commitment();
        let index = shard.index();
        let inner = shard.into_inner();
        let known = seen.entry(commitment).or_default();
        if !known.contains(&inner) {
            known.push(inner.clone());
        }
        let Some(fault) = ShardFault::sample(&mut rng) else {
            continue;
        };
        let mut send = |recipients: Recipients<PublicKeyOf<P>>, shard: ShardOf<P>| {
            let _ = sender.send(recipients, shard.encode(), true);
        };
        match fault {
            ShardFault::Replay => send(Recipients::All, Shard::new(commitment, index, inner)),
            ShardFault::Invalid => send(Recipients::All, Shard::new(commitment, me, inner)),
            ShardFault::Assigned => {
                for (peer_index, peer) in scheme.participants().iter().enumerate() {
                    let peer_index = u16::try_from(peer_index).expect("participant index fits");
                    if peer_index != me {
                        send(
                            Recipients::One(peer.clone()),
                            Shard::new(commitment, peer_index, inner.clone()),
                        );
                    }
                }
            }
            ShardFault::Equivocate => {
                let other = seen
                    .get(&commitment)
                    .and_then(|known| known.iter().find(|known| **known != inner).cloned());
                send(Recipients::All, Shard::new(commitment, me, inner));
                if let Some(other) = other {
                    send(Recipients::All, Shard::new(commitment, me, other));
                }
            }
            ShardFault::Duplicate => {
                for _ in 0..2 {
                    send(Recipients::All, Shard::new(commitment, me, inner.clone()));
                }
            }
            ShardFault::Unknown => send(
                Recipients::All,
                Shard::new(unknown_commitment::<P>(&commitment), me, inner),
            ),
            ShardFault::Garbage => {
                let garbage = Sha256::hash(&[b"coding-garbage-shard", bytes.as_ref()]);
                let _ = sender.send(Recipients::All, garbage.as_ref().to_vec(), true);
            }
        }
    }
}

/// Bytes of a coded block that decode under `expected` but do not describe it.
///
/// The requester must reject them and block the responder. A `WrongConfig` or
/// `WrongBlock` answer fails the codec checks on the coding config or block
/// digest. A `ForgedDigest` answer carries another block whose wire digest
/// claims `expected.block()`, so only the recomputed coding root (untrusted
/// decoding) or the recomputed commitment (trusted decoding) exposes it.
fn poisoned_block<P: Simplex>(
    leader: &PublicKeyOf<P>,
    expected: CommitmentOf<P>,
    poison: BackfillPoison,
) -> Vec<u8> {
    let config = match poison {
        BackfillPoison::WrongBlock | BackfillPoison::ForgedDigest => expected.config(),
        BackfillPoison::WrongConfig => GENESIS_CODING_CONFIG,
    };
    let context = CodingCtx::<P> {
        round: Round::zero(),
        leader: leader.clone(),
        parent: (View::zero(), expected),
    };
    let inner = CodingB::<P>::build(context, expected.block(), Height::new(1), 1);
    let mut encoded = Vec::new();
    inner.write(&mut encoded);
    config.write(&mut encoded);
    if matches!(poison, BackfillPoison::ForgedDigest) {
        // The mock block carries its digest on the wire, right before the
        // trailing coding config.
        let end = encoded.len() - CodingConfig::SIZE;
        let claimed: Sha256Digest = expected.block();
        encoded[end - Sha256Digest::SIZE..end].copy_from_slice(claimed.as_ref());
    }
    encoded
}

/// A quorum notarization for `round` over a payload no node can serve, plus
/// block bytes that decode under it but do not describe it.
///
/// The forgery verifies, so the requester decodes the block and must reject the
/// pair on the block alone. Notarized deliveries recompute the commitment from
/// untrusted bytes, so a forged digest is caught by the coding root, or, with a
/// root over the forged bytes, by the embedded context.
fn poisoned_notarization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    leader: &PublicKeyOf<P>,
    round: Round,
    poison: BackfillPoison,
) -> Option<Vec<u8>>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let n = u16::try_from(schemes[0].participants().len()).expect("participant count fits");
    let config = coding_config_for_participants(n);
    let claimed = Sha256::hash(&[
        b"coding-poison-block",
        round.view().get().to_be_bytes().as_slice(),
    ]);
    let unrooted =
        CommitmentOf::<P>::from((claimed, Sha256Digest::EMPTY, Sha256Digest::EMPTY, config));
    let block = poisoned_block::<P>(leader, unrooted, poison);
    let payload = match poison {
        BackfillPoison::ForgedDigest => {
            let (root, _) = <ReedSolomon<Sha256> as CodingScheme>::encode(
                &config,
                block.as_slice(),
                &Sequential,
            )
            .expect("encoding a block-sized blob succeeds");
            CommitmentOf::<P>::from((claimed, root, Sha256Digest::EMPTY, config))
        }
        BackfillPoison::WrongBlock | BackfillPoison::WrongConfig => unrooted,
    };
    let parent_view = View::new(round.view().get().saturating_sub(1));
    let proposal = Proposal::new(round, parent_view, payload);
    let notarizes = schemes
        .iter()
        .take(QUORUM as usize)
        .map(|scheme| Notarize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()?;
    let notarization =
        Notarization::from_notarizes(&schemes[0], non_empty![@&notarizes], &Sequential).ok()?;
    let mut encoded = notarization.encode().to_vec();
    encoded.extend(block);
    Some(encoded)
}

/// Answers backfill requests with coded blocks that decode but do not match the
/// commitment they are delivered under: block requests directly, and
/// notarized-proposal requests under a forged notarization. Every answer must be
/// rejected as a whole, so the forgery is never stored and only the responder
/// is blocked.
async fn poison_backfill<P: Simplex>(
    schemes: Vec<SchemeOf<P>>,
    leader: PublicKeyOf<P>,
    mut sender: impl Sender<PublicKey = PublicKeyOf<P>>,
    mut receiver: impl Receiver<PublicKey = PublicKeyOf<P>>,
    mut rng: FuzzRng,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    while let Ok((peer, bytes)) = receiver.recv().await {
        let Ok(request) = ResolverMessage::<Key<CommitmentOf<P>>>::decode(bytes) else {
            continue;
        };
        let poison = BackfillPoison::sample(&mut rng);
        let answer = match request.payload {
            ResolverPayload::Request(Key::Block(commitment)) => {
                poisoned_block::<P>(&leader, commitment, poison)
            }
            ResolverPayload::Request(Key::Notarized { round }) => {
                let Some(answer) = poisoned_notarization::<P>(&schemes, &leader, round, poison)
                else {
                    continue;
                };
                answer
            }
            _ => continue,
        };
        let response = ResolverMessage::<Key<CommitmentOf<P>>> {
            id: request.id,
            payload: ResolverPayload::Response(answer.into()),
        };
        let _ = sender.send(Recipients::One(peer), response.encode(), false);
    }
}

/// Starts a Byzantine identity that only poisons block backfill on `backfill`,
/// its marshal backfill channel.
///
/// It is silent on the consensus channels: honest resolvers skip blocked peers,
/// and an equivocating peer is blocked before anyone asks it for a block.
pub(crate) fn start_backfill_poison<P: Simplex>(
    context: deterministic::Context,
    schemes: Vec<SchemeOf<P>>,
    backfill: MarshalNetwork<P>,
    rng: FuzzRng,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let leader = own_key::<P>(&schemes[BYZANTINE_IDX]);
    let (sender, receiver) = backfill;
    context
        .child("backfill_poison")
        .spawn(move |_| poison_backfill::<P>(schemes, leader, sender, receiver, rng));
}

/// Shards of a coded block the Byzantine leader proposes for `view` under a
/// commitment that does not describe the bytes they reconstruct into, plus the
/// commitment to propose.
fn leader_fault_shards<P: Simplex>(
    scheme: &SchemeOf<P>,
    fault: LeaderFault,
    view: View,
    parent: (View, CommitmentOf<P>),
) -> (CommitmentOf<P>, Vec<ShardOf<P>>)
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let n = u16::try_from(scheme.participants().len()).expect("participant count fits");
    let config = coding_config_for_participants(n);
    let context = CodingCtx::<P> {
        round: Round::new(Epoch::zero(), view),
        leader: own_key::<P>(scheme),
        parent,
    };
    let height = Height::new(view.get());
    let inner = CodingB::<P>::build(context, parent.1.block(), height, height.get());
    let context_digest = hash_context::<Sha256, _>(&inner.context());
    match fault {
        LeaderFault::DigestMismatch => {
            let coded = CodingCoded::<P>::new(inner, config, &Sequential);
            let actual = coded.commitment();
            let digest: Sha256Digest = actual.block();
            let commitment = CommitmentOf::<P>::from((
                Sha256::hash(&[b"coding-digest-mismatch", digest.as_ref()]),
                actual.root(),
                actual.context(),
                actual.config(),
            ));
            let shards = (0..n)
                .filter_map(|index| coded.shard(index))
                .map(|shard| Shard::new(commitment, shard.index(), shard.into_inner()))
                .collect();
            (commitment, shards)
        }
        LeaderFault::ConfigMismatch => {
            // The coded bytes carry a config other than the one the shards are
            // checked against, so reconstruction succeeds and validation fails.
            let mut blob = Vec::new();
            inner.write(&mut blob);
            GENESIS_CODING_CONFIG.write(&mut blob);
            let (root, shards) = <ReedSolomon<Sha256> as CodingScheme>::encode(
                &config,
                blob.as_slice(),
                &Sequential,
            )
            .expect("encoding a block-sized blob succeeds");
            let commitment =
                CommitmentOf::<P>::from((inner.digest(), root, context_digest, config));
            let shards = shards
                .into_iter()
                .enumerate()
                .map(|(index, shard)| Shard::new(commitment, index as u16, shard))
                .collect();
            (commitment, shards)
        }
    }
}

/// Start an actor that signs conflicting coding proposals with a Byzantine
/// identity's real key, plus the shard and backfill faults in `faults`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start<P: Simplex>(
    mut context: deterministic::Context,
    scheme: SchemeOf<P>,
    strategy: StrategyChoice,
    required_containers: u64,
    vote_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    faults: CodingFaults<P>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let CodingFaults { shards, mut rng } = faults;
    let seed = CommitmentOf::<P>::from((
        Sha256::hash(&[b"coding-disrupter-seed-block"]),
        Sha256::hash(&[b"coding-disrupter-seed-root"]),
        Sha256::hash(&[b"coding-disrupter-seed-context"]),
        GENESIS_CODING_CONFIG,
    ));
    let faulty_views = fault_views(strategy, required_containers, &mut context);
    let proactive_views = faulty_views
        .clone()
        .unwrap_or_else(|| (1..=required_containers.max(1)).map(View::new).collect());
    let (_, certificate_receiver) = certificate_network;
    context
        .child("certificate_drain")
        .spawn(move |_| drain::<P>(certificate_receiver));
    let (_, resolver_receiver) = resolver_network;
    context
        .child("resolver_drain")
        .spawn(move |_| drain::<P>(resolver_receiver));

    // Leader faults need the shard channel, so they ride with the shard
    // disrupter: half of the runs with a shard channel propose faulty blocks on
    // the views the identity leads instead of the unreconstructable seed.
    let mut leader_faults = None;
    if let Some(((shard_sender, shard_receiver), leads)) = shards {
        let shard_rng = FuzzRng::new(rng.next_u64().to_le_bytes().to_vec());
        let gossip_sender = shard_sender.clone();
        let gossip_scheme = scheme.clone();
        context.child("shard_disrupter").spawn(move |_| {
            disrupt_shards::<P>(gossip_scheme, gossip_sender, shard_receiver, shard_rng)
        });
        if rng.random_range(0..2u8) == 1 {
            leader_faults = Some((shard_sender, leads));
        }
    }

    let (mut vote_sender, mut vote_receiver) = vote_network;
    context.spawn(move |_| async move {
        let mut emitted = HashSet::new();
        let mut proposed = HashSet::new();
        for view in proactive_views {
            if leader_faults.as_ref().is_some_and(|(_, leads)| leads(view)) {
                continue;
            }
            let proposal = Proposal::new(
                Round::new(Epoch::zero(), view),
                View::new(view.get().saturating_sub(1)),
                seed,
            );
            for proposal in [proposal.clone(), conflicting_proposal::<P>(&proposal)] {
                emitted.insert((0u8, proposal.clone()));
                send_notarize::<P>(&scheme, &mut vote_sender, proposal);
            }
        }
        while let Ok((_, message)) = vote_receiver.recv().await {
            let Ok(vote) = Vote::<SchemeOf<P>, CommitmentOf<P>>::decode(message) else {
                continue;
            };
            // A finalize vote for the previous view means honest nodes are
            // entering the next one with that view's commitment as parent.
            if let Some((shard_sender, leads)) = leader_faults.as_mut()
                && let Vote::Finalize(finalize) = &vote
            {
                let parent_view = finalize.view();
                let view = View::new(parent_view.get() + 1);
                if leads(view) && proposed.insert(view) {
                    let parent = (parent_view, finalize.proposal.payload);
                    if let Some(fault) = LeaderFault::sample(&mut rng) {
                        let (commitment, shards) =
                            leader_fault_shards::<P>(&scheme, fault, view, parent);
                        for (peer, shard) in scheme.participants().iter().zip(shards) {
                            let _ = shard_sender.send(
                                Recipients::One(peer.clone()),
                                shard.encode(),
                                true,
                            );
                        }
                        let proposal =
                            Proposal::new(Round::new(Epoch::zero(), view), parent_view, commitment);
                        send_notarize::<P>(&scheme, &mut vote_sender, proposal);
                    }
                }
            }
            if faulty_views
                .as_ref()
                .is_some_and(|views| !views.contains(&vote.view()))
            {
                continue;
            }
            match vote {
                Vote::Notarize(vote) => {
                    let proposals = [
                        vote.proposal.clone(),
                        conflicting_proposal::<P>(&vote.proposal),
                    ];
                    for proposal in proposals {
                        if emitted.insert((0u8, proposal.clone())) {
                            send_notarize::<P>(&scheme, &mut vote_sender, proposal);
                        }
                    }
                }
                Vote::Finalize(vote) => {
                    let proposals = [
                        vote.proposal.clone(),
                        conflicting_proposal::<P>(&vote.proposal),
                    ];
                    for proposal in proposals {
                        if emitted.insert((1u8, proposal.clone())) {
                            send_finalize::<P>(&scheme, &mut vote_sender, proposal);
                        }
                    }
                }
                Vote::Nullify(vote) => {
                    if !emitted.insert((
                        2u8,
                        Proposal::new(vote.round, View::zero(), CommitmentOf::<P>::EMPTY),
                    )) {
                        continue;
                    }
                    let Some(vote) = Nullify::sign::<CommitmentOf<P>>(&scheme, vote.round) else {
                        continue;
                    };
                    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Nullify(vote).encode();
                    let _ = vote_sender.send(Recipients::All, message, true);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus_fuzz_core::SimplexCertificateMock;

    type TestCommitment = CommitmentOf<SimplexCertificateMock>;

    #[test]
    fn conflicting_coding_proposal_preserves_shape_but_changes_payload() {
        let digest = Sha256::hash(&[b"block"]);
        let payload = TestCommitment::from((
            digest,
            Sha256::hash(&[b"root"]),
            Sha256::hash(&[b"context"]),
            commonware_consensus::marshal::mocks::harness::GENESIS_CODING_CONFIG,
        ));
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(1)),
            View::zero(),
            payload,
        );

        let conflicting = conflicting_proposal::<SimplexCertificateMock>(&proposal);
        assert_eq!(conflicting.round, proposal.round);
        assert_eq!(conflicting.parent, proposal.parent);
        assert_ne!(conflicting.payload, proposal.payload);
        assert_eq!(conflicting.payload.config(), proposal.payload.config());
    }
}
