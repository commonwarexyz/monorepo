//! Commitment-typed Byzantine actor for coding end-to-end targets.
//!
//! Besides equivocating on the consensus channels, the actor can disrupt shard
//! dissemination (re-sending mutations of the honest shards it observes and
//! proposing coded blocks whose commitment does not describe their bytes) and
//! poison block backfill (answering block requests with coded blocks that
//! decode but mismatch the requested commitment). Every fault is sampled from
//! the fuzz tape, and each one is attributable to the Byzantine identity alone.
//!
//! In an extended poison run (see [`ExtendedPoison`]) the poisoner also answers
//! with malformed certificates and blocks, and honest nodes hear the Byzantine
//! peer claim to be ahead, so its answers reach marshal's structural checks of
//! notarized and finalized deliveries.

use super::{
    app::BuildableBlock as _,
    coding_stack::{CodingB, CodingCoded, CodingCtx, CodingVariant, CommitmentOf, max_block_size},
    twins::{PublicKeyOf, SchemeOf},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, FixedSize as _, Write as _};
use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as CodingScheme};
use commonware_consensus::{
    CertifiableBlock as _, Viewable,
    marshal::{
        coding::types::{Shard, coding_config_for_participants, hash_context},
        core::Mailbox,
        mocks::{
            block::encode_block,
            harness::{BLOCKS_PER_EPOCH, GENESIS_CODING_CONFIG, QUORUM},
        },
        resolver::handler::Key,
    },
    simplex::{
        scheme::Scheme as SimplexScheme,
        types::{Finalization, Finalize, Notarization, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX,
    byzantine::{self, Counting},
    continuation::{MarkedReceiver, Marker},
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
use commonware_runtime::{Clock as _, Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, SystemTimeExt as _, non_empty, sync::Mutex, vec::NonEmptyVec};
use rand::RngExt as _;
use rand_core::Rng as _;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::Duration,
};

/// Label the consensus-channel equivocation counts under.
pub(crate) const ACTOR: &str = "coding_disrupter";
/// Label the shard faults, replayed and proposed, count under.
pub(crate) const SHARDS_ACTOR: &str = "coding_shards";
/// Label the poisoned backfill answers count under.
pub(crate) const BACKFILL_POISON_ACTOR: &str = "coding_backfill_poison";

/// Claims of being ahead each honest node hears in an extended poison run.
pub(crate) const MAX_HINTS: usize = 2;
/// Longest simulated wait before each claim of being ahead.
pub(crate) const MAX_HINT_DELAY: Duration = Duration::from_secs(2);
/// Most heights a claim puts the Byzantine peer ahead of the node.
pub(crate) const MAX_HINT_AHEAD: u64 = 3;
/// Mask XORed into every input byte to derive the extended poison stream, so it
/// reads the input's first bytes without sharing a stream with the run's other
/// samplers.
pub(crate) const EXTENDED_POISON_MASK: u8 = 0xA5;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackfillPoison {
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
        .index()
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
    mut sender: impl Sender<PublicKey = PublicKeyOf<P>>,
    mut receiver: simulated::Receiver<PublicKeyOf<P>>,
    mut rng: FuzzRng,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let me = own_index::<P>(&scheme);
    let mut seen: BTreeMap<CommitmentOf<P>, Vec<<ReedSolomon<Sha256> as CodingScheme>::Shard>> =
        BTreeMap::new();
    while let Ok((_, bytes)) = receiver.recv().await {
        let Ok(shard) = ShardOf::<P>::decode_cfg(bytes.clone(), &max_block_size::<P>()) else {
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
///
/// Also returns the digest of the block the bytes carry, as built.
pub(crate) fn poisoned_block<P: Simplex>(
    leader: &PublicKeyOf<P>,
    expected: CommitmentOf<P>,
    poison: BackfillPoison,
) -> (Vec<u8>, Sha256Digest) {
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
    (encoded, inner.digest())
}

/// A quorum notarization for `round` over a payload no node can serve, plus
/// block bytes that decode under it but do not describe it.
///
/// The forgery verifies, so the requester decodes the block and must reject the
/// pair on the block alone. Notarized deliveries recompute the commitment from
/// untrusted bytes, so a forged digest is caught by the coding root, or, with a
/// root over the forged bytes, by the embedded context.
///
/// Also returns the digest of the block the bytes carry, as built.
pub(crate) fn poisoned_notarization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    leader: &PublicKeyOf<P>,
    round: Round,
    poison: BackfillPoison,
) -> Option<(Vec<u8>, Sha256Digest)>
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
    let (block, digest) = poisoned_block::<P>(leader, unrooted, poison);
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
    let notarization = forged_notarization::<P>(schemes, proposal)?;
    let mut encoded = notarization.encode().to_vec();
    encoded.extend(block);
    Some((encoded, digest))
}

/// A quorum notarization of `proposal`, signed with the fixture keys.
fn forged_notarization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    proposal: Proposal<CommitmentOf<P>>,
) -> Option<Notarization<SchemeOf<P>, CommitmentOf<P>>>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let notarizes = schemes
        .iter()
        .take(QUORUM as usize)
        .map(|scheme| Notarize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()?;
    Notarization::from_notarizes(&schemes[0], non_empty![@&notarizes], &Sequential).ok()
}

/// A quorum finalization of `proposal`, signed with the fixture keys.
fn forged_finalization<P: Simplex>(
    schemes: &[SchemeOf<P>],
    proposal: Proposal<CommitmentOf<P>>,
) -> Option<Finalization<SchemeOf<P>, CommitmentOf<P>>>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let finalizes = schemes
        .iter()
        .take(QUORUM as usize)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()?;
    Finalization::from_finalizes(&schemes[0], non_empty![@&finalizes], &Sequential).ok()
}

/// The answer kinds of the backfill poisoner. `PoisonedBlock` and
/// `PoisonedNotarization` are the answers of every poison run; the others are
/// sent only in an extended run, each built to fail one structural check of
/// marshal's delivery handling before signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AnswerKind {
    /// [`poisoned_block`] for a block request.
    PoisonedBlock,
    /// [`poisoned_notarization`] for the requested round.
    PoisonedNotarization,
    /// Hash bytes that do not decode as a notarization.
    UndecodableNotarization,
    /// A forged notarization of the next view.
    OtherRound,
    /// A forged notarization whose payload has another coding config.
    BadPayload,
    /// Hash bytes that do not decode as a finalization.
    UndecodableFinalization,
    /// A forged finalization in the epoch after the height's, then a block.
    OtherEpoch,
    /// A forged finalization, then hash bytes that do not decode as a block.
    UndecodableBlock,
    /// A forged finalization of a block one height above the requested one.
    OtherHeight,
    /// A forged finalization, then a block at the height with another digest.
    OtherDigest,
}

impl AnswerKind {
    /// The malformed notarized answers, in draw order after today's (draw 0).
    pub(crate) const NOTARIZED: [Self; 3] = [
        Self::UndecodableNotarization,
        Self::OtherRound,
        Self::BadPayload,
    ];
    /// The finalized answers, in draw order.
    pub(crate) const FINALIZED: [Self; 5] = [
        Self::UndecodableFinalization,
        Self::OtherEpoch,
        Self::UndecodableBlock,
        Self::OtherHeight,
        Self::OtherDigest,
    ];

    /// The label an accepted send of this kind counts under, besides
    /// [`BACKFILL_POISON_ACTOR`]; `None` for the answers of every poison run.
    pub(crate) const fn label(self) -> Option<&'static str> {
        Some(match self {
            Self::PoisonedBlock | Self::PoisonedNotarization => return None,
            Self::UndecodableNotarization => "coding_backfill_poison_undecodable_notarization",
            Self::OtherRound => "coding_backfill_poison_other_round",
            Self::BadPayload => "coding_backfill_poison_bad_payload",
            Self::UndecodableFinalization => "coding_backfill_poison_undecodable_finalization",
            Self::OtherEpoch => "coding_backfill_poison_other_epoch",
            Self::UndecodableBlock => "coding_backfill_poison_undecodable_block",
            Self::OtherHeight => "coding_backfill_poison_other_height",
            Self::OtherDigest => "coding_backfill_poison_other_digest",
        })
    }
}

/// The decision stream of an extended poison run, shared by the poisoner and
/// every honest node's claims of being ahead.
pub(crate) type ExtraRng = Arc<Mutex<FuzzRng>>;

/// The extended mode of a poison run: the decision stream of every choice it adds
/// (`extra_rng`) and the epocher the honest stacks run. Today's samplers keep
/// every draw they make; the extended mode only adds answers and claims.
pub(crate) struct ExtendedPoison {
    rng: ExtraRng,
    epocher: FixedEpocher,
}

impl ExtendedPoison {
    /// Builds `extra_rng` from `raw_bytes`, each byte XORed with
    /// [`EXTENDED_POISON_MASK`], and returns the extended mode when its first draw
    /// selects it. Records the decision.
    pub(crate) fn select(raw_bytes: &[u8]) -> Option<Self> {
        let mut rng = FuzzRng::new(
            raw_bytes
                .iter()
                .map(|byte| byte ^ EXTENDED_POISON_MASK)
                .collect(),
        );
        let extended = rng.random_range(0..2u8) == 1;
        with_records(|records| {
            records.extended = Some(extended);
            records.draws.push(ExtraDraw::Mode(extended));
        });
        extended.then(|| Self {
            rng: Arc::new(Mutex::new(rng)),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        })
    }

    /// The shared decision stream.
    pub(crate) fn rng(&self) -> ExtraRng {
        self.rng.clone()
    }

    /// The answer kind for `key`, drawn from the decision stream: `None` for a
    /// block request, which takes no draw.
    fn draw<P: Simplex>(&self, key: &Key<CommitmentOf<P>>) -> Option<AnswerKind> {
        let kind = match key {
            Key::Block(_) => return None,
            Key::Notarized { .. } => match self.rng.lock().random_range(0..4u8) {
                0 => AnswerKind::PoisonedNotarization,
                draw => AnswerKind::NOTARIZED[usize::from(draw) - 1],
            },
            Key::Finalized { .. } => {
                AnswerKind::FINALIZED[usize::from(self.rng.lock().random_range(0..5u8))]
            }
        };
        with_records(|records| records.draws.push(ExtraDraw::Answer(kind)));
        Some(kind)
    }
}

/// Parent digest of every block an extended answer embeds: no block has it as its
/// digest, so no honest block can share an embedded block's digest.
pub(crate) fn poison_parent(height: Height) -> Sha256Digest {
    Sha256::hash(&[b"poison-parent", height.get().to_be_bytes().as_slice()])
}

/// A block at `height` with the [`poison_parent`] of that height.
fn embedded_block<P: Simplex>(
    leader: &PublicKeyOf<P>,
    round: Round,
    height: Height,
    config: CodingConfig,
) -> CodingB<P> {
    let parent = poison_parent(height);
    let context = CodingCtx::<P> {
        round,
        leader: leader.clone(),
        parent: (
            View::zero(),
            CommitmentOf::<P>::from((parent, Sha256Digest::EMPTY, Sha256Digest::EMPTY, config)),
        ),
    };
    CodingB::<P>::build(context, parent, height, height.get())
}

/// The answer of `kind`, one of [`AnswerKind::NOTARIZED`] or
/// [`AnswerKind::FINALIZED`], to a request for `key`; also returns the digest of
/// the block the answer embeds, if any. `poison` is the draw today's answer uses.
pub(crate) fn extended_answer<P: Simplex>(
    schemes: &[SchemeOf<P>],
    leader: &PublicKeyOf<P>,
    epocher: &FixedEpocher,
    key: &Key<CommitmentOf<P>>,
    kind: AnswerKind,
    poison: BackfillPoison,
) -> Option<(Vec<u8>, Option<Sha256Digest>)>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let n = u16::try_from(schemes[0].participants().len()).expect("participant count fits");
    let config = coding_config_for_participants(n);
    match (*key, kind) {
        (Key::Notarized { round }, AnswerKind::UndecodableNotarization) => Some((
            Sha256::hash(&[b"poison-notarization", round.encode().as_ref()]).to_vec(),
            None,
        )),
        (Key::Notarized { round }, AnswerKind::OtherRound) => {
            let next = Round::new(round.epoch(), View::new(round.view().get() + 1));
            poisoned_notarization::<P>(schemes, leader, next, poison)
                .map(|(bytes, digest)| (bytes, Some(digest)))
        }
        (Key::Notarized { round }, AnswerKind::BadPayload) => {
            let claimed = Sha256::hash(&[b"poison-bad-payload", round.encode().as_ref()]);
            let payload = CommitmentOf::<P>::from((
                claimed,
                Sha256Digest::EMPTY,
                Sha256Digest::EMPTY,
                GENESIS_CODING_CONFIG,
            ));
            let parent = View::new(round.view().get().saturating_sub(1));
            let notarization =
                forged_notarization::<P>(schemes, Proposal::new(round, parent, payload))?;
            Some((notarization.encode().to_vec(), None))
        }
        (Key::Finalized { height }, kind) => {
            let epoch = epocher.containing(height)?.epoch();
            let height_bytes = height.get().to_be_bytes();
            if kind == AnswerKind::UndecodableFinalization {
                let bytes = Sha256::hash(&[b"poison-finalization", height_bytes.as_slice()]);
                return Some((bytes.to_vec(), None));
            }
            let round = Round::new(
                if kind == AnswerKind::OtherEpoch {
                    epoch.next()
                } else {
                    epoch
                },
                View::new(height.get()),
            );
            let (block, block_digest) = match kind {
                AnswerKind::OtherEpoch => {
                    let block = embedded_block::<P>(leader, round, height, config);
                    let digest = block.digest();
                    (Some(block), digest)
                }
                AnswerKind::UndecodableBlock => (
                    None,
                    Sha256::hash(&[b"poison-undecodable-block", height_bytes.as_slice()]),
                ),
                AnswerKind::OtherHeight => {
                    let block = embedded_block::<P>(leader, round, height.next(), config);
                    let digest = block.digest();
                    (Some(block), digest)
                }
                AnswerKind::OtherDigest => {
                    let block = embedded_block::<P>(leader, round, height, config);
                    let digest = Sha256::hash(&[b"poison-other-digest", block.digest().as_ref()]);
                    (Some(block), digest)
                }
                _ => return None,
            };
            let payload = CommitmentOf::<P>::from((
                block_digest,
                Sha256Digest::EMPTY,
                Sha256Digest::EMPTY,
                config,
            ));
            let parent = View::new(round.view().get().saturating_sub(1));
            let finalization =
                forged_finalization::<P>(schemes, Proposal::new(round, parent, payload))?;
            let mut encoded = finalization.encode().to_vec();
            match block {
                Some(block) => {
                    block.write(&mut encoded);
                    Some((encoded, Some(block.digest())))
                }
                None => {
                    let garbage = Sha256::hash(&[b"poison-block", height_bytes.as_slice()]);
                    encoded.extend_from_slice(garbage.as_ref());
                    Some((encoded, None))
                }
            }
        }
        _ => None,
    }
}

/// The key a poisoned answer was requested under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Requested {
    Block,
    Notarized(Round),
    Finalized(Height),
}

/// One answer of the poisoner in an extended run, or in any poison run of a
/// test build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnswerRecord {
    /// Participant index of the requester.
    pub(crate) requester: Option<usize>,
    pub(crate) requested: Requested,
    pub(crate) kind: AnswerKind,
    /// The draw of today's sampler for this request, taken in every poison run.
    pub(crate) legacy_draw: BackfillPoison,
    /// Simulated time of the send.
    pub(crate) at: Duration,
    /// Whether the network accepted the send.
    pub(crate) accepted: bool,
    /// The response payload.
    pub(crate) bytes: Vec<u8>,
}

/// One claim of being ahead an honest node heard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HintRecord {
    pub(crate) node: usize,
    pub(crate) delay: Duration,
    /// The node's processed height when it heard the claim, zero for none.
    pub(crate) processed: u64,
    pub(crate) ahead: u64,
    /// Simulated time of the claim.
    pub(crate) at: Duration,
}

/// One block an honest node's resolver asked its network to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolverBlock {
    pub(crate) node: usize,
    /// Participant index of the blocked peer.
    pub(crate) blocked: Option<usize>,
    /// Simulated time of the block.
    pub(crate) at: Duration,
}

/// One draw from `extra_rng`, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtraDraw {
    Mode(bool),
    Answer(AnswerKind),
    Delay { node: usize, delay: Duration },
    Ahead { node: usize, ahead: u64 },
}

/// What the poison mode of the current run decided and did. Reset at the start
/// of every coding disrupter run; the deterministic runtime runs a run's tasks
/// on the thread that started it, so a run's records stay on that thread.
#[derive(Clone, Debug, Default)]
pub(crate) struct PoisonRecords {
    /// `Some(extended)` once a poison run without a hook chose its mode.
    pub(crate) extended: Option<bool>,
    pub(crate) draws: Vec<ExtraDraw>,
    pub(crate) answers: Vec<AnswerRecord>,
    /// Digests of the blocks the poisoner embedded in its answers.
    pub(crate) embedded: BTreeSet<Sha256Digest>,
    pub(crate) hints: Vec<HintRecord>,
    pub(crate) resolver_blocks: Vec<ResolverBlock>,
}

thread_local! {
    static RECORDS: RefCell<PoisonRecords> = RefCell::new(PoisonRecords::default());
}

fn with_records<T>(f: impl FnOnce(&mut PoisonRecords) -> T) -> T {
    RECORDS.with(|records| f(&mut records.borrow_mut()))
}

/// Clears the records of the previous run on this thread.
pub(crate) fn reset_records() {
    with_records(|records| *records = PoisonRecords::default());
}

/// The records of the current or last run on this thread.
pub(crate) fn records() -> PoisonRecords {
    with_records(|records| records.clone())
}

/// Records a block an honest resolver applied.
pub(crate) fn record_resolver_block(node: usize, blocked: Option<usize>, at: Duration) {
    with_records(|records| {
        records
            .resolver_blocks
            .push(ResolverBlock { node, blocked, at })
    });
}

/// RF-9: no honest application is delivered a block the poisoner embedded.
pub(crate) fn check_not_embedded(node: usize, digest: Sha256Digest) {
    with_records(|records| {
        assert!(
            !records.embedded.contains(&digest),
            "RF-9 violated: node{node} was delivered block {digest}, which the backfill \
             poisoner embedded in an answer"
        );
    });
}

/// RF-8: no honest node is the blocked peer of a `(blocker, blocked)` pair.
pub(crate) fn check_no_honest_blocked<K: PartialEq + std::fmt::Display>(
    blocked: &[(K, K)],
    participants: &[K],
) {
    for (blocker, peer) in blocked {
        let index = participants.iter().position(|key| key == peer);
        assert!(
            index.is_none_or(|index| index == BYZANTINE_IDX),
            "RF-8 violated: honest node{} ({peer}) was blocked by {blocker}",
            index.unwrap_or(usize::MAX),
        );
    }
}

/// RF-7, for the fixed tests: some requester's resolver blocked the Byzantine
/// peer, and every answer the poisoner sent it at or before that block (at
/// least one) is of `kind`.
#[cfg(test)]
pub(crate) fn check_resolver_block_witness(records: &PoisonRecords, kind: AnswerKind) {
    let mut seen = BTreeSet::new();
    let mut witnessed = Vec::new();
    for block in &records.resolver_blocks {
        if block.blocked != Some(BYZANTINE_IDX) || !seen.insert(block.node) {
            continue;
        }
        let sent: Vec<AnswerKind> = records
            .answers
            .iter()
            .filter(|answer| {
                answer.accepted && answer.requester == Some(block.node) && answer.at <= block.at
            })
            .map(|answer| answer.kind)
            .collect();
        if !sent.is_empty() && sent.iter().all(|sent| *sent == kind) {
            return;
        }
        witnessed.push((block.node, block.at, sent));
    }
    panic!(
        "RF-7 violated: no resolver blocked the Byzantine peer after answers of {kind:?} \
         alone; first blocks and the answers before them: {witnessed:?}"
    );
}

/// One answer of the backfill poisoner, as [`answer_request`] chooses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoisonAnswer {
    pub(crate) kind: AnswerKind,
    /// The draw of today's sampler for this message.
    pub(crate) legacy_draw: BackfillPoison,
    pub(crate) requested: Requested,
    /// The response payload.
    pub(crate) bytes: Vec<u8>,
    /// Digest of the block the answer embeds, as built.
    pub(crate) embedded: Option<Sha256Digest>,
}

/// The poisoner's answer to one decoded backfill message; `None` when it does
/// not answer. Today's sampler draws from `rng` for every message, as it always
/// has. A block request takes no other draw; with `extended`, a notarized or
/// finalized request takes its answer kind from the extended stream.
pub(crate) fn answer_request<P: Simplex>(
    schemes: &[SchemeOf<P>],
    leader: &PublicKeyOf<P>,
    rng: &mut FuzzRng,
    payload: ResolverPayload<Key<CommitmentOf<P>>>,
    extended: Option<&ExtendedPoison>,
) -> Option<PoisonAnswer>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let poison = BackfillPoison::sample(rng);
    let ResolverPayload::Request(key) = payload else {
        return None;
    };
    let kind = match (extended, key) {
        (_, Key::Block(_)) => AnswerKind::PoisonedBlock,
        (None, Key::Notarized { .. }) => AnswerKind::PoisonedNotarization,
        (None, Key::Finalized { .. }) => return None,
        (Some(extended), key) => extended
            .draw::<P>(&key)
            .expect("a certificate request draws its answer"),
    };
    let (bytes, embedded) = match (key, kind) {
        (Key::Block(commitment), _) => {
            let (bytes, digest) = poisoned_block::<P>(leader, commitment, poison);
            (bytes, Some(digest))
        }
        (Key::Notarized { round }, AnswerKind::PoisonedNotarization) => {
            let (bytes, digest) = poisoned_notarization::<P>(schemes, leader, round, poison)?;
            (bytes, Some(digest))
        }
        (key, kind) => extended.and_then(|extended| {
            extended_answer::<P>(schemes, leader, &extended.epocher, &key, kind, poison)
        })?,
    };
    let requested = match key {
        Key::Block(_) => Requested::Block,
        Key::Notarized { round } => Requested::Notarized(round),
        Key::Finalized { height } => Requested::Finalized(height),
    };
    Some(PoisonAnswer {
        kind,
        legacy_draw: poison,
        requested,
        bytes,
        embedded,
    })
}

/// Answers backfill requests with coded blocks that decode but do not match the
/// commitment they are delivered under: block requests directly, and
/// notarized-proposal requests under a forged notarization. Every answer must be
/// rejected as a whole, so the forgery is never stored and only the responder
/// is blocked. With `extended`, notarized and finalized requests also get the
/// malformed answers of [`AnswerKind`], and every answer is recorded; test
/// builds also record the answers of a run without it.
async fn poison_backfill<P: Simplex>(
    context: deterministic::Context,
    schemes: Vec<SchemeOf<P>>,
    leader: PublicKeyOf<P>,
    mut sender: impl Sender<PublicKey = PublicKeyOf<P>>,
    mut receiver: impl Receiver<PublicKey = PublicKeyOf<P>>,
    mut rng: FuzzRng,
    extended: Option<ExtendedPoison>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    while let Ok((peer, bytes)) = receiver.recv().await {
        let Ok(request) = ResolverMessage::<Key<CommitmentOf<P>>>::decode(bytes) else {
            continue;
        };
        let Some(answer) = answer_request::<P>(
            &schemes,
            &leader,
            &mut rng,
            request.payload,
            extended.as_ref(),
        ) else {
            continue;
        };
        let response = ResolverMessage::<Key<CommitmentOf<P>>> {
            id: request.id,
            payload: ResolverPayload::Response(answer.bytes.clone().into()),
        };
        let accepted = !sender
            .send(Recipients::One(peer.clone()), response.encode(), false)
            .is_empty();
        if extended.is_none() && !cfg!(test) {
            continue;
        }
        if extended.is_some()
            && accepted
            && let Some(label) = answer.kind.label()
        {
            byzantine::record(label);
        }
        let record = AnswerRecord {
            requester: schemes[0].participants().position(&peer),
            requested: answer.requested,
            kind: answer.kind,
            legacy_draw: answer.legacy_draw,
            at: context.current().epoch(),
            accepted,
            bytes: answer.bytes,
        };
        with_records(|records| {
            if extended.is_some() {
                records.embedded.extend(answer.embedded);
            }
            records.answers.push(record);
        });
    }
}

/// Starts a Byzantine identity that only poisons block backfill on `backfill`,
/// its marshal backfill channel; returns its task. `marker` is set when the task
/// first polls its receiver.
///
/// It is silent on the consensus channels: honest resolvers skip blocked peers,
/// and an equivocating peer is blocked before anyone asks it for a block.
pub(crate) fn start_backfill_poison<P: Simplex>(
    context: deterministic::Context,
    schemes: Vec<SchemeOf<P>>,
    backfill: MarshalNetwork<P>,
    rng: FuzzRng,
    marker: Option<Marker>,
    extended: Option<ExtendedPoison>,
) -> Handle<()>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let leader = own_key::<P>(&schemes[BYZANTINE_IDX]);
    let (sender, receiver) = backfill;
    context.child("backfill_poison").spawn(move |context| {
        poison_backfill::<P>(
            context,
            schemes,
            leader,
            Counting::new(sender, BACKFILL_POISON_ACTOR),
            MarkedReceiver::new(receiver, marker),
            rng,
            extended,
        )
    })
}

/// Starts honest node `node`'s claims of being ahead (child context `claims`):
/// [`MAX_HINTS`] times, after a delay drawn from `extra_rng`, the Byzantine
/// `target` claims a finalized block a drawn [`MAX_HINT_AHEAD`] or fewer heights
/// above the node's processed height. Only a targeted fetch asks the poisoner for
/// a finalization.
pub(crate) fn start_claims<P: Simplex>(
    context: &deterministic::Context,
    node: usize,
    mailbox: Mailbox<SchemeOf<P>, CodingVariant<P>>,
    rng: ExtraRng,
    target: PublicKeyOf<P>,
) -> Handle<()> {
    context.child("claims").spawn(move |context| async move {
        let max_delay = u64::try_from(MAX_HINT_DELAY.as_millis()).expect("delay fits");
        for _ in 0..MAX_HINTS {
            let delay = Duration::from_millis(rng.lock().random_range(0..=max_delay));
            with_records(|records| records.draws.push(ExtraDraw::Delay { node, delay }));
            context.sleep(delay).await;
            let processed = mailbox
                .get_processed()
                .await
                .map_or(0, |processed| processed.height().get());
            let ahead = rng.lock().random_range(1..=MAX_HINT_AHEAD);
            with_records(|records| {
                records.draws.push(ExtraDraw::Ahead { node, ahead });
                records.hints.push(HintRecord {
                    node,
                    delay,
                    processed,
                    ahead,
                    at: context.current().epoch(),
                });
            });
            mailbox.hint_finalized(
                Height::new(processed + ahead),
                NonEmptyVec::new(target.clone()),
            );
        }
    })
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
            let coded: CodingCoded<P> = encode_block(inner, config);
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
/// identity's real key, plus the shard and backfill faults in `faults`; returns
/// the task that votes. Its sampled views are moved `view_offset` views later, so
/// an actor started after a continuation's prefix targets the views that follow;
/// `marker` is set when the voting task first polls its vote receiver.
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
    view_offset: u64,
    marker: Option<Marker>,
) -> Handle<()>
where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let CodingFaults { shards, mut rng } = faults;
    let seed = CommitmentOf::<P>::from((
        Sha256::hash(&[b"coding-disrupter-seed-block"]),
        Sha256::hash(&[b"coding-disrupter-seed-root"]),
        Sha256::hash(&[b"coding-disrupter-seed-context"]),
        GENESIS_CODING_CONFIG,
    ));
    let shift = |view: View| View::new(view.get().saturating_add(view_offset));
    let faulty_views = fault_views(strategy, required_containers, &mut context)
        .map(|views| views.into_iter().map(shift).collect::<Vec<_>>());
    let proactive_views = faulty_views.clone().unwrap_or_else(|| {
        (1..=required_containers.max(1))
            .map(|view| shift(View::new(view)))
            .collect()
    });
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
        let shard_sender = Counting::new(shard_sender, SHARDS_ACTOR);
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

    let (vote_sender, vote_receiver) = vote_network;
    let mut vote_receiver = MarkedReceiver::new(vote_receiver, marker);
    let mut vote_sender = Counting::new(vote_sender, ACTOR);
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
    })
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

    fn answer(requester: usize, kind: AnswerKind, at: u64) -> AnswerRecord {
        AnswerRecord {
            requester: Some(requester),
            requested: Requested::Finalized(Height::new(1)),
            kind,
            legacy_draw: BackfillPoison::WrongBlock,
            at: Duration::from_millis(at),
            accepted: true,
            bytes: Vec::new(),
        }
    }

    fn block(node: usize, at: u64) -> ResolverBlock {
        ResolverBlock {
            node,
            blocked: Some(BYZANTINE_IDX),
            at: Duration::from_millis(at),
        }
    }

    #[test]
    fn resolver_block_witness_needs_one_kind_before_the_block() {
        let records = PoisonRecords {
            answers: vec![
                answer(1, AnswerKind::OtherEpoch, 10),
                answer(2, AnswerKind::OtherHeight, 10),
                answer(2, AnswerKind::OtherEpoch, 20),
                answer(2, AnswerKind::OtherHeight, 40),
            ],
            resolver_blocks: vec![block(1, 15), block(2, 30)],
            ..PoisonRecords::default()
        };
        check_resolver_block_witness(&records, AnswerKind::OtherEpoch);
        for kind in [AnswerKind::OtherHeight, AnswerKind::OtherDigest] {
            let panic = std::panic::catch_unwind(|| check_resolver_block_witness(&records, kind))
                .expect_err("no requester has a block after answers of this kind alone");
            let message = panic.downcast_ref::<String>().expect("formatted panic");
            assert!(message.starts_with("RF-7 violated"), "{message}");
        }
    }
}
