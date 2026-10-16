//! The consensus-critical parameters and genesis of one epoch.

use super::Error;
use crate::{
    Epochable,
    multimmit::types::{ChainId, CodecConfig, CodecConfigError, EpochGenesis, Window},
    types::{Epoch, Participant, Round, View},
};
use bytes::Bytes;
use commonware_cryptography::Digest;
use commonware_utils::{Faults as _, N5f1};
use std::{collections::HashSet, sync::Arc};

/// A deterministic view-to-leader schedule for one epoch.
///
/// Multimmit fixes one leader per view from an immutable rotation, so the schedule is a plain
/// cycle of participants that every node evaluates identically. [`LeaderSchedule::round_robin`] is
/// the protocol default; [`LeaderSchedule::from_fn`] materializes any deterministic leader
/// function whose schedule repeats with the committee period.
///
/// Randomized election is not supported; the
/// [proposal transition](crate::multimmit::docs::state_machine#proposal) explains why.
///
/// The schedule is consensus-critical: changing it requires a new deployment namespace (see
/// [`Parameters::new`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderSchedule(Arc<[Participant]>);

impl LeaderSchedule {
    /// Returns the protocol default: participant `view % n` leads `view`.
    ///
    /// # Errors
    ///
    /// Returns an error if `participants` is zero or exceeds `u32::MAX`.
    pub fn round_robin(participants: usize) -> Result<Self, Error> {
        participant_count(participants)?;
        Self::from_order(
            (0..participants).map(Participant::from_usize).collect(),
            participants,
        )
    }

    /// Materializes the schedule `elect` returns for `epoch`.
    ///
    /// `elect` maps a round to its leader, for example a simplex
    /// [`RoundRobinElector`](crate::simplex::elector::RoundRobinElector) called without a
    /// certificate. It is evaluated once per view over one committee period and must repeat with
    /// that period, which every rotation-style schedule does. A function that does not repeat
    /// cannot be expressed as an immutable epoch schedule and is rejected.
    pub fn from_fn(
        elect: impl Fn(Round) -> Participant,
        epoch: Epoch,
        participants: usize,
    ) -> Result<Self, Error> {
        participant_count(participants)?;
        let period = participants as u64;
        let mut order = Vec::with_capacity(participants);
        for view in 0..period {
            let leader = elect(Round::new(epoch, View::new(view)));
            if leader.get() as usize >= participants {
                return Err(Error::LeaderSchedule);
            }
            order.push(leader);
        }
        // Reject a schedule that does not repeat with the committee period: it could not be stored
        // as one immutable cycle without silently changing the leader of later views.
        for view in period..(period * 2) {
            let expected = order[(view % period) as usize];
            if elect(Round::new(epoch, View::new(view))) != expected {
                return Err(Error::LeaderSchedule);
            }
        }
        Self::from_order(order, participants)
    }

    /// Returns an explicit rotation over a committee of `participants` members.
    ///
    /// # Errors
    ///
    /// Returns an error if `participants` is zero or exceeds `u32::MAX`, or if `order` has a
    /// different length, names a non-member, or contains fewer than `f + 1` distinct committee
    /// members.
    pub fn from_order(order: Vec<Participant>, participants: usize) -> Result<Self, Error> {
        let schedule = Self(order.into());
        schedule.validate(participants)?;
        Ok(schedule)
    }

    fn validate(&self, participants: usize) -> Result<(), Error> {
        let participants_u32 = participant_count(participants)?;
        if self.0.len() != participants {
            return Err(Error::LeaderSchedule);
        }

        let required = (N5f1::max_faults(participants_u32) + 1) as usize;
        let mut distinct = HashSet::with_capacity(required);
        for &participant in self.0.iter() {
            if participant.get() >= participants_u32 {
                return Err(Error::LeaderSchedule);
            }
            if distinct.len() < required {
                distinct.insert(participant);
            }
        }
        if distinct.len() < required {
            return Err(Error::LeaderSchedule);
        }

        Ok(())
    }

    /// Returns the leader of `view`.
    pub fn leader(&self, view: View) -> Participant {
        self.0[(view.get() % self.0.len() as u64) as usize]
    }
}

/// Returns `participants` as a protocol identifier count, rejecting the counts
/// [`CodecConfig::new`] rejects with the same errors.
fn participant_count(participants: usize) -> Result<u32, Error> {
    if participants == 0 {
        return Err(CodecConfigError::ZeroParticipants.into());
    }
    u32::try_from(participants)
        .map_err(|_| CodecConfigError::TooManyParticipants(participants).into())
}

/// The consensus-critical parameters of one epoch, apart from its genesis.
///
/// A signing [`Scheme`](crate::multimmit::scheme::bls12381::Scheme) holds these, and an
/// engine builds its [`Protocol`] from the scheme's copy, so the two cannot disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    epoch: Epoch,
    namespace: Bytes,
    codec_config: CodecConfig,
    producers: Arc<[Participant]>,
    leaders: LeaderSchedule,
}

impl Parameters {
    /// Validates and creates the parameters of an epoch with a round-robin leader schedule, an
    /// adoption quorum of `f + 1`, and the default V-QC byte ceiling.
    ///
    /// `namespace` identifies the deployment. It must be globally unique and change whenever any
    /// consensus-critical configuration changes. Deployments should derive it from a digest of
    /// their configuration manifest. Participant `i` produces chain `j` when `producers[j] == i`.
    pub fn new(
        epoch: Epoch,
        namespace: &[u8],
        participants: usize,
        producers: Vec<Participant>,
        window: Window,
    ) -> Result<Self, Error> {
        let codec_config = CodecConfig::new(participants, producers.len(), window)?;
        let mut unique = HashSet::with_capacity(producers.len());
        for &producer in &producers {
            if producer.get() as usize >= participants {
                return Err(Error::ProducerOutOfRange(producer));
            }
            if !unique.insert(producer) {
                return Err(Error::DuplicateProducer(producer));
            }
        }

        Ok(Self {
            epoch,
            namespace: Bytes::copy_from_slice(namespace),
            codec_config,
            producers: producers.into(),
            leaders: LeaderSchedule::round_robin(participants)?,
        })
    }

    /// Replaces the round-robin default with an explicit deterministic schedule.
    ///
    /// # Errors
    ///
    /// Returns an error if the schedule has the wrong committee size, names a non-member, or
    /// contains fewer than `f + 1` distinct committee members.
    pub fn with_leaders(mut self, leaders: LeaderSchedule) -> Result<Self, Error> {
        leaders.validate(self.codec_config.participants())?;
        self.leaders = leaders;
        Ok(self)
    }

    /// Replaces the adoption quorum `alpha`: the endorsers that let a validator accept a block whose
    /// body it has not verified.
    ///
    /// # Errors
    ///
    /// Returns an error unless `f + 1 <= adoption <= n - 2f`. At least `f + 1` keeps an invalid
    /// block from being adopted, since some correct endorser verified it; at most `n - 2f` keeps
    /// every block that correct validators endorse adoptable.
    pub fn with_adoption(mut self, adoption: u32) -> Result<Self, Error> {
        self.codec_config = self.codec_config.with_adoption(adoption)?;
        Ok(self)
    }

    /// Replaces the ceiling on one encoded V-QC.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is zero.
    pub fn with_max_vqc_bytes(mut self, bytes: u32) -> Result<Self, Error> {
        self.codec_config = self.codec_config.with_max_vqc_bytes(bytes)?;
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
            .zip(0u32..)
            .find_map(|(producer, index)| (*producer == participant).then(|| ChainId::new(index)))
    }

    /// Returns producers in chain-index order.
    pub fn producers(&self) -> &[Participant] {
        &self.producers
    }

    /// Returns the deployment namespace used for signature domain separation.
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Returns the epoch's window.
    pub const fn window(&self) -> Window {
        self.codec_config.window()
    }

    /// Returns bounded decode configuration for this epoch.
    pub const fn codec_config(&self) -> CodecConfig {
        self.codec_config
    }
}

impl Epochable for Parameters {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Validated immutable configuration for one Multimmit epoch: its [`Parameters`] and genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol<D: Digest> {
    parameters: Arc<Parameters>,
    // Copied out of the parameters so the machine's const size derivations can read it.
    codec_config: CodecConfig,
    genesis: EpochGenesis<D>,
}

impl<D: Digest> Protocol<D> {
    /// Validates and creates an immutable epoch configuration for `genesis`'s epoch with a
    /// round-robin leader schedule.
    ///
    /// See [`Parameters::new`] for `namespace` and `producers`.
    pub fn new(
        namespace: &[u8],
        participants: usize,
        producers: Vec<Participant>,
        window: Window,
        genesis: EpochGenesis<D>,
    ) -> Result<Self, Error> {
        let parameters =
            Parameters::new(genesis.epoch(), namespace, participants, producers, window)?;
        Self::from_parameters(Arc::new(parameters), genesis)
    }

    /// Pairs `parameters` with the epoch's `genesis`.
    ///
    /// # Errors
    ///
    /// Returns an error unless `genesis` belongs to the parameters' epoch and names one tip per
    /// producer chain.
    pub fn from_parameters(
        parameters: Arc<Parameters>,
        genesis: EpochGenesis<D>,
    ) -> Result<Self, Error> {
        if genesis.epoch() != parameters.epoch() {
            return Err(Error::GenesisEpoch {
                expected: parameters.epoch(),
                actual: genesis.epoch(),
            });
        }
        let chains = parameters.producers().len();
        if genesis.tips().len() != chains {
            return Err(Error::GenesisTips {
                expected: chains,
                actual: genesis.tips().len(),
            });
        }
        Ok(Self {
            codec_config: parameters.codec_config(),
            parameters,
            genesis,
        })
    }

    /// Replaces the round-robin default with an explicit deterministic schedule.
    ///
    /// # Errors
    ///
    /// Returns an error if the schedule has the wrong committee size, names a non-member, or
    /// contains fewer than `f + 1` distinct committee members.
    pub fn with_leaders(self, leaders: LeaderSchedule) -> Result<Self, Error> {
        let parameters = Arc::unwrap_or_clone(self.parameters).with_leaders(leaders)?;
        Ok(Self {
            parameters: Arc::new(parameters),
            codec_config: self.codec_config,
            genesis: self.genesis,
        })
    }

    /// Returns the epoch's parameters, shared with its signing scheme.
    pub const fn parameters(&self) -> &Arc<Parameters> {
        &self.parameters
    }

    /// Returns the epoch's immutable leader schedule.
    pub fn leaders(&self) -> &LeaderSchedule {
        self.parameters.leaders()
    }

    /// Returns the scheduled leader of `view`.
    pub fn leader(&self, view: View) -> Participant {
        self.parameters.leader(view)
    }

    /// Returns the producer assigned to `chain`.
    pub fn producer(&self, chain: ChainId) -> Option<Participant> {
        self.parameters.producer(chain)
    }

    /// Returns the producer chain assigned to `participant`.
    pub fn producer_chain(&self, participant: Participant) -> Option<ChainId> {
        self.parameters.producer_chain(participant)
    }

    /// Returns producers in chain-index order.
    pub fn producers(&self) -> &[Participant] {
        self.parameters.producers()
    }

    /// Returns the deployment namespace used for signature domain separation.
    pub fn namespace(&self) -> &[u8] {
        self.parameters.namespace()
    }

    /// Returns the epoch's window.
    pub fn window(&self) -> Window {
        self.parameters.window()
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

impl<D: Digest> Epochable for Protocol<D> {
    fn epoch(&self) -> Epoch {
        self.parameters.epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::ChainId;
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};

    fn genesis(epoch: Epoch, chains: usize) -> EpochGenesis<Sha256Digest> {
        EpochGenesis::new::<Sha256>(epoch, chains).unwrap()
    }

    fn window() -> Window {
        Window::new(2).unwrap()
    }

    fn producers(count: u32) -> Vec<Participant> {
        (0..count).map(Participant::new).collect()
    }

    /// Returns a leader function that cycles through `order` by view.
    fn fixed_cycle(order: Vec<Participant>) -> impl Fn(Round) -> Participant {
        move |round| order[round.view().get() as usize % order.len()]
    }

    #[test]
    fn scheduled_leaders_follow_round_robin_order() {
        for participants in [1usize, 6, 7] {
            for view in 1..=(participants as u64 * 2) {
                assert_eq!(
                    LeaderSchedule::round_robin(participants)
                        .unwrap()
                        .leader(View::new(view)),
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
            let order = |order: Vec<u32>| order.into_iter().map(Participant::new).collect();

            assert_eq!(
                LeaderSchedule::from_order(order(insufficient), participants),
                Err(Error::LeaderSchedule)
            );
            assert!(LeaderSchedule::from_order(order(sufficient), participants).is_ok());
        }
    }

    #[test]
    fn leader_schedules_reject_an_empty_committee() {
        let zero = || Error::Codec(CodecConfigError::ZeroParticipants);
        assert_eq!(LeaderSchedule::round_robin(0).unwrap_err(), zero());
        assert_eq!(
            LeaderSchedule::from_order(Vec::new(), 0).unwrap_err(),
            zero()
        );
        assert_eq!(
            LeaderSchedule::from_fn(|_| Participant::new(0), Epoch::new(7), 0).unwrap_err(),
            zero()
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn leader_schedules_reject_participant_overflow_like_codec_config() {
        let participants = u32::MAX as usize + 1;
        let too_many = || Error::Codec(CodecConfigError::TooManyParticipants(participants));
        assert_eq!(
            Error::from(CodecConfig::new(participants, 1, window()).unwrap_err()),
            too_many()
        );
        assert_eq!(
            LeaderSchedule::round_robin(participants).unwrap_err(),
            too_many()
        );
        assert_eq!(
            LeaderSchedule::from_order(vec![Participant::new(0)], participants).unwrap_err(),
            too_many()
        );
        assert_eq!(
            LeaderSchedule::from_fn(|_| Participant::new(0), Epoch::new(7), participants)
                .unwrap_err(),
            too_many()
        );
    }

    #[test]
    fn elector_cycles_require_f_plus_one_distinct_members() {
        let epoch = Epoch::new(7);
        let insufficient = fixed_cycle(vec![Participant::new(0); 6]);
        assert_eq!(
            LeaderSchedule::from_fn(insufficient, epoch, 6),
            Err(Error::LeaderSchedule)
        );

        let sufficient = fixed_cycle(
            [0, 1, 0, 1, 0, 1]
                .into_iter()
                .map(Participant::new)
                .collect(),
        );
        assert!(LeaderSchedule::from_fn(sufficient, epoch, 6).is_ok());
    }

    #[test]
    fn config_revalidates_attached_leader_cycles() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_LEADER_CYCLE_TEST";
        let config =
            Protocol::new(namespace, 6, producers(6), window(), genesis(epoch, 6)).unwrap();
        let insufficient = LeaderSchedule(vec![Participant::new(0); 6].into());

        assert_eq!(
            config.with_leaders(insufficient),
            Err(Error::LeaderSchedule)
        );
    }

    #[test]
    fn config_validates_genesis_epoch_and_tip_count() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CONFIG_TEST";

        let protocol =
            Protocol::new(namespace, 2, producers(2), window(), genesis(epoch, 2)).unwrap();
        assert_eq!(protocol.epoch(), epoch, "the epoch is the genesis epoch");
        // Parameters dealt for one epoch cannot pair with another epoch's genesis.
        assert_eq!(
            Protocol::from_parameters(Arc::clone(protocol.parameters()), genesis(Epoch::new(8), 2))
                .unwrap_err(),
            Error::GenesisEpoch {
                expected: epoch,
                actual: Epoch::new(8),
            }
        );
        assert_eq!(
            Protocol::new(namespace, 2, producers(2), window(), genesis(epoch, 1)).unwrap_err(),
            Error::GenesisTips {
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn config_assigns_non_contiguous_validator_producers() {
        let epoch = Epoch::new(7);
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PRODUCERS_TEST";
        let assigned = vec![Participant::new(5), Participant::new(2)];
        let config =
            Protocol::new(namespace, 6, assigned.clone(), window(), genesis(epoch, 2)).unwrap();

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

        assert_eq!(
            Protocol::new(
                namespace,
                6,
                vec![Participant::new(6)],
                window(),
                genesis(epoch, 1),
            )
            .unwrap_err(),
            Error::ProducerOutOfRange(Participant::new(6))
        );
        assert_eq!(
            Protocol::new(
                namespace,
                6,
                vec![Participant::new(2), Participant::new(2)],
                window(),
                genesis(epoch, 2),
            )
            .unwrap_err(),
            Error::DuplicateProducer(Participant::new(2))
        );
    }

    #[test]
    fn parameters_bound_the_adoption_quorum() {
        let parameters =
            Parameters::new(Epoch::new(7), b"_TEST", 11, producers(11), window()).unwrap();
        assert_eq!(parameters.codec_config().adoption_quorum(), 3);
        assert_eq!(
            parameters.clone().with_adoption(2).unwrap_err(),
            Error::Codec(CodecConfigError::AdoptionRange(2))
        );
        assert_eq!(
            parameters
                .clone()
                .with_adoption(7)
                .unwrap()
                .codec_config()
                .adoption_quorum(),
            7
        );
        assert_eq!(
            parameters.clone().with_adoption(8).unwrap_err(),
            Error::Codec(CodecConfigError::AdoptionRange(8))
        );
        assert_eq!(
            parameters.with_max_vqc_bytes(0).unwrap_err(),
            Error::Codec(CodecConfigError::ZeroVqcBytes)
        );
    }
}
