//! Immutable Multimmit configuration.

use super::types::{ChainId, EpochGenesis};
use crate::{
    Epochable,
    elector::Elector,
    types::{Epoch, Participant, Round, View},
};
use bytes::Bytes;
use commonware_codec::{EncodeSize, FixedSize, varint::UInt};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::N5f1;
use std::{collections::HashSet, sync::Arc};

/// Resource limits that are immutable within an epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pipeline_depth: u32,
    extension_bound: u32,
}

impl Limits {
    /// Creates protocol path limits.
    ///
    /// A pipeline must admit at least one block. An extension bound of zero is
    /// valid and disables vote extensions.
    pub const fn new(pipeline_depth: u32, extension_bound: u32) -> Result<Self, ConfigError> {
        if pipeline_depth == 0 {
            return Err(ConfigError::ZeroPipelineDepth);
        }

        Ok(Self {
            pipeline_depth,
            extension_bound,
        })
    }

    /// Returns the maximum number of blocks appended by one chain proposal.
    pub const fn pipeline_depth(self) -> u32 {
        self.pipeline_depth
    }

    /// Returns the maximum number of blocks carried by one vote extension.
    pub const fn extension_bound(self) -> u32 {
        self.extension_bound
    }
}

/// Bounded inputs used while decoding untrusted protocol objects.
///
/// Counts are stored as `u32` so their meaning is independent of the target
/// architecture. Getters convert them to allocation and indexing sizes only
/// after construction has validated both counts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CodecConfig {
    participants: u32,
    chains: u32,
    limits: Limits,
}

impl CodecConfig {
    /// Creates bounded codec configuration for an epoch.
    pub fn new(participants: usize, chains: usize, limits: Limits) -> Result<Self, ConfigError> {
        if participants == 0 {
            return Err(ConfigError::ZeroParticipants);
        }
        if chains == 0 {
            return Err(ConfigError::ZeroChains);
        }

        let participants = u32::try_from(participants)
            .map_err(|_| ConfigError::TooManyParticipants(participants))?;
        let chains = u32::try_from(chains).map_err(|_| ConfigError::TooManyChains(chains))?;

        Ok(Self {
            participants,
            chains,
            limits,
        })
    }

    /// Returns the exact number of participants.
    pub const fn participants(self) -> usize {
        self.participants as usize
    }

    /// Returns the exact number of producer chains.
    pub const fn chains(self) -> usize {
        self.chains as usize
    }

    /// Returns the maximum number of blocks in one chain proposal.
    pub const fn pipeline_depth(self) -> usize {
        self.limits.pipeline_depth as usize
    }

    /// Returns the maximum number of blocks in one vote extension.
    pub const fn extension_bound(self) -> usize {
        self.limits.extension_bound as usize
    }

    /// Returns the exact DA-certificate quorum, `n - 2f`.
    pub fn da_quorum(self) -> usize {
        N5f1::n_minus_two_f(self.participants) as usize
    }

    /// Returns the exact nullification quorum, `2f + 1`.
    pub fn nullification_quorum(self) -> usize {
        N5f1::m_quorum(self.participants) as usize
    }

    /// Returns the minimum messages accounted by a V-QC and the exact L-QC quorum, `n - f`.
    pub fn view_quorum(self) -> usize {
        N5f1::l_quorum(self.participants) as usize
    }

    /// Returns the maximum number of messages accounted by a V-QC, `n`.
    pub const fn vqc_max_messages(self) -> usize {
        self.participants()
    }

    /// Returns the minimum votes required for a V-QC designation, `2f + 1`.
    pub fn designation_quorum(self) -> usize {
        N5f1::m_quorum(self.participants) as usize
    }

    /// Computes exact encoded maxima for this epoch's bounded protocol objects.
    pub(crate) fn encoded_bounds<V: Variant, D: Digest>(
        self,
    ) -> Result<EncodedBounds, BoundsError> {
        let sizes = ProtocolSizes::new::<V, D>(self)?;
        let envelope = checked_sum(&[1, MAX_U64_VARINT_SIZE])?;

        let max_artifact_bytes = sizes.max_artifact();
        let proposal_group = checked_sum(&[sizes.vqc, sizes.signed_leader])?;
        let max_ingress_group_bytes = max_artifact_bytes.max(proposal_group);
        let max_data_frame_bytes = checked_sum(&[
            envelope,
            1,
            sizes
                .signed_transaction
                .max(sizes.da_vote)
                .max(sizes.da_certificate),
        ])?;
        let proposal = checked_sum(&[1, proposal_group])?;
        let max_consensus_frame_bytes = checked_sum(&[
            envelope,
            1,
            proposal
                .max(sizes.vote)
                .max(sizes.no_vote)
                .max(sizes.nullify),
        ])?;
        let max_certificate_frame_bytes = checked_sum(&[
            envelope,
            1,
            sizes.nullification.max(sizes.vqc).max(sizes.lqc),
        ])?;

        Ok(EncodedBounds {
            max_artifact_bytes,
            max_ingress_group_bytes,
            max_data_frame_bytes,
            max_consensus_frame_bytes,
            max_certificate_frame_bytes,
        })
    }
}

const MAX_U64_VARINT_SIZE: usize = 10;

/// Exact encoded maxima derived from an immutable epoch codec configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedBounds {
    max_artifact_bytes: usize,
    max_ingress_group_bytes: usize,
    max_data_frame_bytes: usize,
    max_consensus_frame_bytes: usize,
    max_certificate_frame_bytes: usize,
}

impl EncodedBounds {
    pub(crate) const fn max_artifact_bytes(self) -> usize {
        self.max_artifact_bytes
    }

    pub(crate) const fn max_ingress_group_bytes(self) -> usize {
        self.max_ingress_group_bytes
    }

    pub(crate) const fn max_data_frame_bytes(self) -> usize {
        self.max_data_frame_bytes
    }

    pub(crate) const fn max_consensus_frame_bytes(self) -> usize {
        self.max_consensus_frame_bytes
    }

    pub(crate) const fn max_certificate_frame_bytes(self) -> usize {
        self.max_certificate_frame_bytes
    }
}

/// An encoded maximum cannot be represented on this target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BoundsError {
    #[error("encoded size bound exceeds usize")]
    Overflow,
}

struct ProtocolSizes {
    signed_transaction: usize,
    da_vote: usize,
    da_certificate: usize,
    signed_leader: usize,
    vote: usize,
    no_vote: usize,
    nullify: usize,
    nullification: usize,
    vqc: usize,
    lqc: usize,
}

impl ProtocolSizes {
    fn new<V: Variant, D: Digest>(config: CodecConfig) -> Result<Self, BoundsError> {
        let n = config.participants();
        let k = config.chains();
        let d = config.pipeline_depth();
        let e = config.extension_bound();
        let digest = D::SIZE;
        let signature = V::Signature::SIZE;
        let participant = max_participant_width(n)?;
        let chain = max_index_width(k)?;

        let header = checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            checked_product(2, digest)?,
            chain,
        ])?;
        let signed_transaction = checked_sum(&[header, participant, signature])?;
        let da_vote = signed_transaction;
        let da_certificate = checked_sum(&[header, signature])?;

        let proposal_payloads = encoded_vec(d, digest)?;
        let proposal_without_chain = checked_sum(&[
            1,
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            checked_product(2, digest)?,
            signature,
            proposal_payloads,
        ])?;
        let proposals = checked_sum(&[
            encoded_len(k)?,
            checked_product(k, proposal_without_chain)?,
            encoded_index_sum(k)?,
        ])?;
        let leader = checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            checked_product(2, digest)?,
            proposals,
        ])?;
        let signed_leader = checked_sum(&[leader, participant, signature])?;

        let extension = encoded_vec(e, digest)?;
        let extensions = encoded_vec(k, extension)?;
        let positions = encoded_vec(k, encoded_len(d)?)?;
        let vote_body = checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            digest,
            positions,
            extensions,
        ])?;
        let vote = checked_sum(&[vote_body, participant, signature])?;
        let no_vote = checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            participant,
            signature,
        ])?;
        let nullify = no_vote;
        let nullification = checked_sum(&[checked_product(2, MAX_U64_VARINT_SIZE)?, signature])?;

        // Signers wraps BitMap<1>, which prefixes its bit count with a fixed-width u64.
        let bitmap = checked_sum(&[u64::SIZE, n.div_ceil(8)])?;
        let position_deviation = checked_sum(&[
            encoded_len(k)?,
            encoded_index_sum(k)?,
            checked_product(k, encoded_len(d - 1)?)?,
        ])?;
        let replacement_extensions = if e == 0 { 0 } else { extensions };
        let tally_without_signers = |votes: usize| -> Result<usize, BoundsError> {
            checked_sum(&[
                extensions,
                bitmap,
                encoded_len(votes)?,
                checked_product(votes, checked_sum(&[position_deviation, 1])?)?,
                checked_product(votes.saturating_sub(1), replacement_extensions)?,
            ])
        };
        let tally = |votes: usize| -> Result<usize, BoundsError> {
            checked_sum(&[
                tally_without_signers(votes)?,
                largest_index_width_sum(n, votes)?,
            ])
        };

        let quorum = config.view_quorum();
        let vqc_max = config.vqc_max_messages();
        let designation = config.designation_quorum();
        let lqc = checked_sum(&[leader, tally(quorum)?, signature])?;
        let conflicting_vote = checked_sum(&[digest, positions, extensions])?;
        let mut vqc = 0;
        for votes in vqc_candidates(designation, vqc_max) {
            let conflicting = vqc_max - votes;
            let candidate = checked_sum(&[
                leader,
                tally_without_signers(votes)?,
                largest_index_width_sum(n, vqc_max)?,
                bitmap,
                encoded_len(conflicting)?,
                checked_product(conflicting, conflicting_vote)?,
                signature,
            ])?;
            vqc = vqc.max(candidate);
        }

        Ok(Self {
            signed_transaction,
            da_vote,
            da_certificate,
            signed_leader,
            vote,
            no_vote,
            nullify,
            nullification,
            vqc,
            lqc,
        })
    }

    fn max_artifact(&self) -> usize {
        [
            self.signed_transaction,
            self.da_vote,
            self.da_certificate,
            self.signed_leader,
            self.vote,
            self.no_vote,
            self.nullify,
            self.nullification,
            self.vqc,
            self.lqc,
        ]
        .into_iter()
        .max()
        .expect("artifact set is non-empty")
    }
}

fn checked_sum(values: &[usize]) -> Result<usize, BoundsError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
        .ok_or(BoundsError::Overflow)
}

fn checked_product(left: usize, right: usize) -> Result<usize, BoundsError> {
    left.checked_mul(right).ok_or(BoundsError::Overflow)
}

fn encoded_len(value: usize) -> Result<usize, BoundsError> {
    let value = u32::try_from(value).map_err(|_| BoundsError::Overflow)?;
    Ok(UInt(value).encode_size())
}

fn encoded_vec(count: usize, item_size: usize) -> Result<usize, BoundsError> {
    checked_sum(&[encoded_len(count)?, checked_product(count, item_size)?])
}

fn max_participant_width(participants: usize) -> Result<usize, BoundsError> {
    max_index_width(participants)
}

fn max_index_width(count: usize) -> Result<usize, BoundsError> {
    encoded_len(count - 1)
}

fn encoded_index_sum(participants: usize) -> Result<usize, BoundsError> {
    const ENDS: [u64; 5] = [1 << 7, 1 << 14, 1 << 21, 1 << 28, 1 << 32];

    let participants = u64::try_from(participants).map_err(|_| BoundsError::Overflow)?;
    let mut start = 0u64;
    let mut total = 0usize;
    for (index, end) in ENDS.into_iter().enumerate() {
        let count = participants.min(end).saturating_sub(start);
        let count = usize::try_from(count).map_err(|_| BoundsError::Overflow)?;
        total = checked_sum(&[total, checked_product(count, index + 1)?])?;
        if participants <= end {
            return Ok(total);
        }
        start = end;
    }
    Err(BoundsError::Overflow)
}

fn largest_index_width_sum(participants: usize, count: usize) -> Result<usize, BoundsError> {
    let first = participants
        .checked_sub(count)
        .ok_or(BoundsError::Overflow)?;
    encoded_index_sum(participants)?
        .checked_sub(encoded_index_sum(first)?)
        .ok_or(BoundsError::Overflow)
}

fn vqc_candidates(minimum: usize, maximum: usize) -> Vec<usize> {
    const BOUNDARIES: [usize; 4] = [1 << 7, 1 << 14, 1 << 21, 1 << 28];

    let mut candidates = vec![minimum, maximum];
    for boundary in BOUNDARIES {
        candidates.extend([boundary.saturating_sub(1), boundary]);
        if maximum >= boundary {
            candidates.extend([maximum - boundary, maximum - boundary + 1]);
        }
    }
    candidates.retain(|candidate| (*candidate >= minimum) && (*candidate <= maximum));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

impl Default for CodecConfig {
    fn default() -> Self {
        Self {
            participants: 1,
            chains: 1,
            limits: Limits {
                pipeline_depth: 1,
                extension_bound: 0,
            },
        }
    }
}

/// Errors returned while constructing immutable epoch configuration.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// No participant was configured.
    #[error("participant count must be non-zero")]
    ZeroParticipants,
    /// The participant count cannot be represented by protocol identifiers.
    #[error("participant count {0} exceeds u32::MAX")]
    TooManyParticipants(usize),
    /// No producer chain was configured.
    #[error("producer chain count must be non-zero")]
    ZeroChains,
    /// The producer chain count cannot be represented by protocol identifiers.
    #[error("producer chain count {0} exceeds u32::MAX")]
    TooManyChains(usize),
    /// A producer is not a validator in this epoch.
    #[error("producer {0} is outside the participant set")]
    ProducerOutOfRange(Participant),
    /// A validator was assigned more than one producer chain.
    #[error("participant {0} owns more than one producer chain")]
    DuplicateProducer(Participant),
    /// The proposal pipeline cannot admit a block.
    #[error("pipeline depth must be non-zero")]
    ZeroPipelineDepth,
    /// Genesis names another epoch.
    #[error("genesis epoch {actual} does not match configuration epoch {expected}")]
    GenesisEpoch { expected: Epoch, actual: Epoch },
    /// The leader schedule does not match the epoch's participant set.
    #[error("invalid leader schedule")]
    LeaderSchedule,
    /// Genesis does not define exactly one tip per participant chain.
    #[error("genesis has {actual} tips but configuration requires {expected}")]
    GenesisTips { expected: usize, actual: usize },
}

/// A deterministic view-to-leader schedule for one epoch.
///
/// Multimmit fixes one leader per view from an immutable rotation, so the schedule is a plain
/// cycle of participants that every node evaluates identically. [`LeaderSchedule::round_robin`] is
/// the protocol default; [`LeaderSchedule::from_elector`] materializes any deterministic
/// [`Elector`] whose schedule repeats with the committee period.
///
/// # Randomized election
///
/// Multimmit does not support VRF or otherwise randomized election. Unpredictable election needs a
/// unique per-view value, and Multimmit's ordinary exit path produces none: a V-QC is an aggregate
/// of ordinary signatures, which is not unique and can be ground by its assembler. Only the
/// nullification path yields a threshold signature, and it covers just the views that time out.
/// Adding randomized election therefore requires a new machine-visible seed, not a different
/// elector.
///
/// The schedule is consensus-critical. A deployment namespace must be globally unique and must
/// change whenever the schedule, protocol limits, or any other consensus-critical configuration
/// changes. Deployments should derive it from a digest of their configuration manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderSchedule(Arc<[Participant]>);

impl LeaderSchedule {
    /// Returns the protocol default: participant `view % n` leads `view`.
    ///
    /// # Panics
    ///
    /// Panics if `participants` is zero or exceeds `u32::MAX`.
    pub fn round_robin(participants: usize) -> Self {
        assert!(participants > 0, "leader schedule requires participants");
        assert!(
            u32::try_from(participants).is_ok(),
            "leader schedule participant count exceeds u32::MAX"
        );

        Self::from_cycle(
            (0..participants).map(Participant::from_usize).collect(),
            participants,
        )
        .expect("round-robin cycle is valid")
    }

    /// Materializes `elector`'s schedule for `epoch`.
    ///
    /// The elector is evaluated once per view over one committee period and must repeat with that
    /// period, which every rotation-style schedule does. An elector that does not repeat cannot be
    /// expressed as an immutable epoch schedule and is rejected.
    pub fn from_elector<E: Elector<()>>(
        elector: &E,
        epoch: Epoch,
        participants: usize,
    ) -> Result<Self, ConfigError> {
        if participants == 0 {
            return Err(ConfigError::ZeroParticipants);
        }
        if u32::try_from(participants).is_err() {
            return Err(ConfigError::LeaderSchedule);
        }
        let period = participants as u64;
        let mut order = Vec::with_capacity(participants);
        for view in 0..period {
            let leader = elector.elect(Round::new(epoch, View::new(view)), None);
            if leader.get() as usize >= participants {
                return Err(ConfigError::LeaderSchedule);
            }
            order.push(leader);
        }
        // Reject a schedule that does not repeat with the committee period: it could not be stored
        // as one immutable cycle without silently changing the leader of later views.
        for view in period..(period * 2) {
            let expected = order[(view % period) as usize];
            if elector.elect(Round::new(epoch, View::new(view)), None) != expected {
                return Err(ConfigError::LeaderSchedule);
            }
        }
        Self::from_cycle(order, participants)
    }

    /// Returns a schedule with the same committee size and an explicit rotation.
    ///
    /// # Errors
    ///
    /// Returns an error if `order` has a different length, names a non-member, or contains fewer
    /// than `f + 1` distinct committee members.
    pub fn clone_with(&self, order: Vec<Participant>) -> Result<Self, ConfigError> {
        Self::from_cycle(order, self.0.len())
    }

    fn from_cycle(order: Vec<Participant>, participants: usize) -> Result<Self, ConfigError> {
        let schedule = Self(order.into());
        schedule.validate(participants)?;
        Ok(schedule)
    }

    fn validate(&self, participants: usize) -> Result<(), ConfigError> {
        let Ok(participants_u32) = u32::try_from(participants) else {
            return Err(ConfigError::LeaderSchedule);
        };
        if participants_u32 == 0 || self.0.len() != participants {
            return Err(ConfigError::LeaderSchedule);
        }

        let required = N5f1::f_plus_one(participants_u32) as usize;
        let mut distinct = HashSet::with_capacity(required);
        for &participant in self.0.iter() {
            if participant.get() >= participants_u32 {
                return Err(ConfigError::LeaderSchedule);
            }
            if distinct.len() < required {
                distinct.insert(participant);
            }
        }
        if distinct.len() < required {
            return Err(ConfigError::LeaderSchedule);
        }

        Ok(())
    }

    /// Returns the leader of `view`.
    pub fn leader(&self, view: View) -> Participant {
        self.0[(view.get() % self.0.len() as u64) as usize]
    }
}

/// Validated immutable configuration for one Multimmit epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config<D: Digest> {
    epoch: Epoch,
    namespace: Bytes,
    genesis: EpochGenesis<D>,
    codec_config: CodecConfig,
    producers: Arc<[Participant]>,
    leaders: LeaderSchedule,
}

impl<D: Digest> Config<D> {
    /// Validates and creates an immutable epoch configuration.
    ///
    /// `namespace` identifies the deployment. It must be globally unique and change whenever any
    /// consensus-critical configuration changes. Deployments should derive it from a digest of
    /// their configuration manifest.
    pub fn new(
        epoch: Epoch,
        namespace: &[u8],
        participants: usize,
        producers: Vec<Participant>,
        limits: Limits,
        genesis: EpochGenesis<D>,
    ) -> Result<Self, ConfigError> {
        let codec_config = CodecConfig::new(participants, producers.len(), limits)?;
        let mut unique = HashSet::with_capacity(producers.len());
        for &producer in &producers {
            if producer.get() as usize >= participants {
                return Err(ConfigError::ProducerOutOfRange(producer));
            }
            if !unique.insert(producer) {
                return Err(ConfigError::DuplicateProducer(producer));
            }
        }

        if genesis.epoch() != epoch {
            return Err(ConfigError::GenesisEpoch {
                expected: epoch,
                actual: genesis.epoch(),
            });
        }
        if genesis.tips().len() != producers.len() {
            return Err(ConfigError::GenesisTips {
                expected: producers.len(),
                actual: genesis.tips().len(),
            });
        }

        Ok(Self {
            epoch,
            namespace: Bytes::copy_from_slice(namespace),
            genesis,
            codec_config,
            producers: producers.into(),
            leaders: LeaderSchedule::round_robin(participants),
        })
    }

    /// Replaces the round-robin default with an explicit deterministic schedule.
    ///
    /// # Errors
    ///
    /// Returns an error if the schedule has the wrong committee size, names a non-member, or
    /// contains fewer than `f + 1` distinct committee members.
    pub fn with_leaders(mut self, leaders: LeaderSchedule) -> Result<Self, ConfigError> {
        leaders.validate(self.codec_config.participants())?;
        self.leaders = leaders;
        Ok(self)
    }

    /// Returns the epoch's immutable leader schedule.
    pub const fn leaders(&self) -> &LeaderSchedule {
        &self.leaders
    }

    /// Returns the scheduled leader of `view`.
    pub fn leader(&self, view: View) -> Participant {
        self.leaders.leader(view)
    }

    /// Returns the producer assigned to `chain`.
    pub fn producer(&self, chain: ChainId) -> Option<Participant> {
        self.producers.get(chain.get() as usize).copied()
    }

    /// Returns the producer chain assigned to `participant`.
    pub fn producer_chain(&self, participant: Participant) -> Option<ChainId> {
        self.producers
            .iter()
            .position(|producer| *producer == participant)
            .map(|index| {
                ChainId::new(u32::try_from(index).expect("validated chain index fits u32"))
            })
    }

    /// Returns producers in chain-index order.
    pub fn producers(&self) -> &[Participant] {
        &self.producers
    }

    /// Returns the epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the deployment namespace used for signature domain separation.
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Returns the immutable protocol limits.
    pub const fn limits(&self) -> Limits {
        self.codec_config.limits
    }

    /// Returns the epoch's synthetic genesis facts.
    pub const fn genesis(&self) -> &EpochGenesis<D> {
        &self.genesis
    }

    /// Returns bounded decode configuration for this epoch.
    pub const fn codec_config(&self) -> CodecConfig {
        self.codec_config
    }
}

impl<D: Digest> Epochable for Config<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elector::Terms,
        multimmit::types::{BlockRef, CertificateId, ChainId, Height},
    };
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };

    fn genesis(epoch: Epoch, participants: u32) -> EpochGenesis<Sha256Digest> {
        let tips = (0..participants)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    Sha256::hash(&[&chain.to_be_bytes()]),
                )
            })
            .collect();

        EpochGenesis::new(
            epoch,
            Sha256::hash(&[b"leader genesis"]),
            CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
            CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
            tips,
        )
        .unwrap()
    }

    fn producers(count: u32) -> Vec<Participant> {
        (0..count).map(Participant::new).collect()
    }

    #[derive(Clone)]
    struct FixedCycle(Vec<Participant>);

    impl Elector<()> for FixedCycle {
        fn terms(&self) -> Terms {
            Terms::rotating()
        }

        fn elect(&self, round: Round, _evidence: Option<&()>) -> Participant {
            self.0[round.view().get() as usize % self.0.len()]
        }
    }

    #[test]
    fn zero_extension_bound_is_valid() {
        let limits = Limits::new(1, 0).unwrap();
        assert_eq!(limits.pipeline_depth(), 1);
        assert_eq!(limits.extension_bound(), 0);

        let codec = CodecConfig::new(1, 1, limits).unwrap();
        assert_eq!(codec.pipeline_depth(), 1);
        assert_eq!(codec.extension_bound(), 0);
    }

    #[test]
    fn scheduled_leaders_follow_round_robin_order() {
        for participants in [1usize, 6, 7] {
            for view in 1..=(participants as u64 * 2) {
                assert_eq!(
                    LeaderSchedule::round_robin(participants).leader(View::new(view)),
                    Participant::from_usize(view as usize % participants),
                );
            }
        }
    }

    #[test]
    fn explicit_leader_cycles_require_f_plus_one_distinct_members() {
        for (participants, insufficient, sufficient) in [
            (6, vec![0, 0, 0, 0, 0, 0], vec![0, 1, 0, 1, 0, 1]),
            (
                11,
                vec![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                vec![0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1],
            ),
        ] {
            let schedule = LeaderSchedule::round_robin(participants);
            let participants = |order: Vec<u32>| order.into_iter().map(Participant::new).collect();

            assert_eq!(
                schedule.clone_with(participants(insufficient)),
                Err(ConfigError::LeaderSchedule)
            );
            assert!(schedule.clone_with(participants(sufficient)).is_ok());
        }
    }

    #[test]
    fn elector_cycles_require_f_plus_one_distinct_members() {
        let epoch = Epoch::new(7);
        let insufficient = FixedCycle(vec![Participant::new(0); 6]);
        assert_eq!(
            LeaderSchedule::from_elector(&insufficient, epoch, 6),
            Err(ConfigError::LeaderSchedule)
        );

        let sufficient = FixedCycle(
            [0, 1, 0, 1, 0, 1]
                .into_iter()
                .map(Participant::new)
                .collect(),
        );
        assert!(LeaderSchedule::from_elector(&sufficient, epoch, 6).is_ok());
    }

    #[test]
    fn config_revalidates_attached_leader_cycles() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_LEADER_CYCLE_TEST";
        let limits = Limits::new(2, 0).unwrap();
        let config =
            Config::new(epoch, namespace, 6, producers(6), limits, genesis(epoch, 6)).unwrap();
        let insufficient = LeaderSchedule(vec![Participant::new(0); 6].into());

        assert_eq!(
            config.with_leaders(insufficient),
            Err(ConfigError::LeaderSchedule)
        );
    }

    #[test]
    fn rejects_zero_pipeline_depth_and_participants() {
        assert_eq!(Limits::new(0, 0), Err(ConfigError::ZeroPipelineDepth));
        assert_eq!(
            CodecConfig::new(0, 1, Limits::new(1, 0).unwrap()),
            Err(ConfigError::ZeroParticipants)
        );
        assert_eq!(
            CodecConfig::new(1, 0, Limits::new(1, 0).unwrap()),
            Err(ConfigError::ZeroChains)
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_participant_count_above_u32() {
        let participants = u32::MAX as usize + 1;
        assert_eq!(
            CodecConfig::new(participants, 1, Limits::new(1, 0).unwrap()),
            Err(ConfigError::TooManyParticipants(participants))
        );
        assert_eq!(
            CodecConfig::new(1, participants, Limits::new(1, 0).unwrap()),
            Err(ConfigError::TooManyChains(participants))
        );
    }

    #[test]
    fn codec_config_derives_n5f1_quorums() {
        for (participants, chains) in [(1, 1), (5, 2), (6, 1), (10, 4), (11, 6), (16, 3)] {
            let codec = CodecConfig::new(
                participants as usize,
                chains as usize,
                Limits::new(4, 3).unwrap(),
            )
            .unwrap();

            assert_eq!(codec.participants(), participants as usize);
            assert_eq!(codec.chains(), chains as usize);
            assert_eq!(
                codec.da_quorum(),
                N5f1::n_minus_two_f(participants) as usize
            );
            assert_eq!(
                codec.nullification_quorum(),
                N5f1::m_quorum(participants) as usize
            );
            assert_eq!(codec.view_quorum(), N5f1::l_quorum(participants) as usize);
            assert_eq!(
                codec.designation_quorum(),
                N5f1::m_quorum(participants) as usize
            );
        }
    }

    #[test]
    fn default_codec_config_is_safe() {
        let codec = CodecConfig::default();
        assert_eq!(codec.participants(), 1);
        assert_eq!(codec.chains(), 1);
        assert_eq!(codec.pipeline_depth(), 1);
        assert_eq!(codec.extension_bound(), 0);
    }

    #[test]
    fn checked_encoded_bounds_reject_overflow_without_allocating() {
        let codec = CodecConfig::new(
            u32::MAX as usize,
            u32::MAX as usize,
            Limits::new(u32::MAX, u32::MAX).unwrap(),
        )
        .unwrap();

        assert_eq!(
            codec.encoded_bounds::<MinPk, Sha256Digest>(),
            Err(BoundsError::Overflow)
        );
        assert_eq!(
            codec.encoded_bounds::<MinSig, Sha256Digest>(),
            Err(BoundsError::Overflow)
        );
    }

    #[test]
    fn encoded_bounds_include_the_exact_largest_decoded_ingress_group() {
        for (participants, chains, pipeline_depth, extension_bound) in
            [(1, 1, 1, 0), (6, 2, 3, 1), (11, 7, 64, 32)]
        {
            let codec = CodecConfig::new(
                participants,
                chains,
                Limits::new(pipeline_depth, extension_bound).unwrap(),
            )
            .unwrap();
            let sizes = ProtocolSizes::new::<MinPk, Sha256Digest>(codec).unwrap();
            let expected = sizes
                .max_artifact()
                .max(sizes.vqc.checked_add(sizes.signed_leader).unwrap());

            assert_eq!(
                codec
                    .encoded_bounds::<MinPk, Sha256Digest>()
                    .unwrap()
                    .max_ingress_group_bytes(),
                expected,
            );
        }
    }

    #[test]
    fn config_validates_genesis_epoch_and_tip_count() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CONFIG_TEST";
        let limits = Limits::new(2, 0).unwrap();

        assert!(Config::new(epoch, namespace, 2, producers(2), limits, genesis(epoch, 2)).is_ok());
        assert_eq!(
            Config::new(
                epoch,
                namespace,
                2,
                producers(2),
                limits,
                genesis(Epoch::new(8), 2)
            )
            .unwrap_err(),
            ConfigError::GenesisEpoch {
                expected: epoch,
                actual: Epoch::new(8),
            }
        );
        assert_eq!(
            Config::new(epoch, namespace, 2, producers(2), limits, genesis(epoch, 1)).unwrap_err(),
            ConfigError::GenesisTips {
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn config_assigns_non_contiguous_validator_producers() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PRODUCERS_TEST";
        let limits = Limits::new(2, 0).unwrap();
        let assigned = vec![Participant::new(5), Participant::new(2)];
        let config = Config::new(
            epoch,
            namespace,
            6,
            assigned.clone(),
            limits,
            genesis(epoch, 2),
        )
        .unwrap();

        assert_eq!(config.codec_config().participants(), 6);
        assert_eq!(config.codec_config().chains(), 2);
        assert_eq!(config.producers(), assigned);
        assert_eq!(config.producer(ChainId::new(0)), Some(Participant::new(5)));
        assert_eq!(config.producer(ChainId::new(1)), Some(Participant::new(2)));
        assert_eq!(config.producer(ChainId::new(2)), None);
        assert_eq!(
            config.producer_chain(Participant::new(5)),
            Some(ChainId::new(0))
        );
        assert_eq!(config.producer_chain(Participant::new(0)), None);
    }

    #[test]
    fn config_rejects_invalid_producer_assignments() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PRODUCERS_REJECT_TEST";
        let limits = Limits::new(2, 0).unwrap();

        assert_eq!(
            Config::new(
                epoch,
                namespace,
                6,
                vec![Participant::new(6)],
                limits,
                genesis(epoch, 1),
            )
            .unwrap_err(),
            ConfigError::ProducerOutOfRange(Participant::new(6))
        );
        assert_eq!(
            Config::new(
                epoch,
                namespace,
                6,
                vec![Participant::new(2), Participant::new(2)],
                limits,
                genesis(epoch, 2),
            )
            .unwrap_err(),
            ConfigError::DuplicateProducer(Participant::new(2))
        );
    }
}
