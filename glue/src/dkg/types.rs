//! Shared types for the DKG module.

use crate::dkg::network::Directory;
use bytes::Buf;
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Output, PlayerAck, SignedDealerLog},
        primitives::{
            group::Share,
            sharing::{ModeVersion, Sharing},
            variant::Variant,
        },
    },
};
use commonware_p2p::TrackedPeers;
use commonware_utils::{Faults as _, N3f1, ordered::Set, sequence::Unit};
use std::num::{NonZeroU32, NonZeroU64};
use thiserror::Error;

/// Information required to construct an epoch-scoped threshold scheme that may
/// or may not be capable of signing messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemeInfo<V: Variant, P: PublicKey> {
    /// Information required for constructing a verifier scheme.
    Verifier {
        /// The participants.
        participants: Set<P>,
        /// The public group polynomial.
        sharing: Sharing<V>,
    },
    /// Information required for constructing a signer scheme.
    Signer {
        /// The participants.
        participants: Set<P>,
        /// The public group polynomial.
        sharing: Sharing<V>,
        /// A BLS [`Share`].
        share: Share,
    },
}

/// Result of a completed DKG/reshare epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EncodeSize, Read, Write)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum EpochOutcome {
    /// The epoch produced a new public output.
    #[codec(tag = 0)]
    Success,
    /// The epoch failed and carried the previous public state forward.
    #[codec(tag = 1)]
    Failure,
}

/// Participants for a DKG/reshare epoch.
#[derive(Clone, Debug, PartialEq, Eq, EncodeSize, Write)]
pub struct Participants<P: PublicKey> {
    /// Peers that distribute dealings in this epoch.
    pub dealers: Set<P>,
    /// Peers that receive shares in this epoch.
    pub players: Set<P>,
    /// Players of the next epoch, tracked early for connectivity.
    pub next_players: Set<P>,
}

/// Errors produced while validating DKG/reshare participants.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParticipantsError {
    /// No dealers were provided.
    #[error("dealers must not be empty")]
    EmptyDealers,
    /// No players were provided.
    #[error("players must not be empty")]
    EmptyPlayers,
    /// A participant set exceeds the configured maximum.
    #[error("too many participants: {actual} > {max}")]
    TooManyParticipants { actual: usize, max: usize },
    /// Round-zero reshare dealers differ from the previous output players.
    #[error("round-zero reshare dealers must equal previous output players")]
    InitialReshareDealers,
    /// A later reshare dealer does not own a previous share.
    #[error("reshare dealer is not a previous player")]
    UnknownReshareDealer,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EpochCapacityError {
    available: u64,
    required: u64,
}

impl<P: PublicKey> Participants<P> {
    /// Builds the peer set used by the DKG channel.
    ///
    /// Dealers are the primary tracked peers because they send protocol data in the
    /// current round. Current and next players are tracked as secondary peers so the
    /// actor keeps enough connectivity to receive its own messages and prepare the
    /// next epoch without allowing next players to act as dealers.
    pub fn tracked_peers(&self) -> TrackedPeers<P> {
        TrackedPeers::new(
            self.dealers.clone(),
            Set::from_iter_dedup(self.players.iter().chain(self.next_players.iter()).cloned()),
        )
    }

    /// Checks that a participant snapshot is usable for the requested reshare round.
    ///
    /// Reshare requires non-empty dealer and player sets, caps every participant set
    /// at `max_participants`, and verifies that reshare dealers are authorized by the
    /// previous epoch output. Round zero must start from exactly the previous player
    /// set. Later rounds may use any subset of previous players as dealers.
    pub fn validate<V: Variant>(
        &self,
        max_participants: NonZeroU32,
        previous: Option<&Output<V, P>>,
        round: u64,
    ) -> Result<(), ParticipantsError> {
        if self.dealers.is_empty() {
            return Err(ParticipantsError::EmptyDealers);
        }
        if self.players.is_empty() {
            return Err(ParticipantsError::EmptyPlayers);
        }

        let max = max_participants.get() as usize;
        for actual in [
            self.dealers.len(),
            self.players.len(),
            self.next_players.len(),
        ] {
            if actual > max {
                return Err(ParticipantsError::TooManyParticipants { actual, max });
            }
        }

        let Some(previous) = previous else {
            return Ok(());
        };

        if round == 0 {
            if &self.dealers != previous.players() {
                return Err(ParticipantsError::InitialReshareDealers);
            }
            return Ok(());
        }

        if self
            .dealers
            .iter()
            .any(|dealer| previous.players().position(dealer).is_none())
        {
            return Err(ParticipantsError::UnknownReshareDealer);
        }

        Ok(())
    }

    pub(crate) fn validate_epoch_capacity<V: Variant>(
        &self,
        blocks_per_epoch: NonZeroU64,
        previous: Option<&Output<V, P>>,
    ) -> Result<(), EpochCapacityError> {
        let available = dealer_log_slots(blocks_per_epoch);
        let required = self.required_dealer_logs(previous);
        if available < required {
            return Err(EpochCapacityError {
                available,
                required,
            });
        }
        Ok(())
    }

    fn required_dealer_logs<V: Variant>(&self, previous: Option<&Output<V, P>>) -> u64 {
        let dealer_quorum = u64::from(N3f1::quorum(self.dealers.len()));
        let previous_quorum = previous
            .map(|previous| u64::from(previous.quorum::<N3f1>()))
            .unwrap_or_default();
        dealer_quorum.max(previous_quorum)
    }
}

const fn dealer_log_slots(blocks_per_epoch: NonZeroU64) -> u64 {
    let blocks = blocks_per_epoch.get();
    // Shorter epochs do not leave a usable dealing-to-inclusion window.
    if blocks < 4 {
        return 0;
    }
    blocks.saturating_sub(blocks / 2 + 1)
}

impl<P: PublicKey> Read for Participants<P> {
    /// Maximum number of participants accepted in any single set.
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, max: &Self::Cfg) -> Result<Self, CodecError> {
        let cfg = (RangeCfg::new(0..=max.get() as usize), ());
        Ok(Self {
            dealers: Set::read_cfg(reader, &cfg)?,
            players: Set::read_cfg(reader, &cfg)?,
            next_players: Set::read_cfg(reader, &cfg)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::network::Addresses;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        bls12381::{
            dkg::feldman_desmedt::deal,
            primitives::{sharing::Mode, variant::MinPk},
        },
        ed25519,
    };
    use commonware_p2p::Address;
    use commonware_utils::{NZU32, NZU64, TestRng};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn keys(count: u64) -> Set<ed25519::PublicKey> {
        Set::from_iter_dedup(
            (0..count).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        )
    }

    fn addresses(keys: &Set<ed25519::PublicKey>) -> Addresses<ed25519::PublicKey> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), index as u16 + 1);
                (key.clone(), Address::Symmetric(socket))
            })
            .collect()
    }

    fn addressed_info(
        participants: u64,
    ) -> EpochInfo<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>> {
        let keys = keys(participants);
        let (output, _) =
            deal::<MinPk, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, keys.clone())
                .expect("trusted deal");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(2),
            output,
            players: keys.clone(),
            next_players: keys.clone(),
            directory: addresses(&keys),
        }
    }

    #[test]
    fn addressed_epoch_info_roundtrips() {
        let info = addressed_info(4);
        let decoded =
            EpochInfo::<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>>::decode_cfg(
                info.encode(),
                &(NZU32!(4), crate::dkg::tests::max_supported_mode()),
            )
            .expect("decode addressed epoch info");
        assert_eq!(decoded, info);
    }

    #[test]
    fn addressed_epoch_info_roundtrips_disjoint_participant_sets() {
        let dealers = keys(4);
        let players = Set::from_iter_dedup(
            (4..8).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let next_players = Set::from_iter_dedup(
            (8..12).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let peers = Set::from_iter_dedup(
            dealers
                .iter()
                .chain(players.iter())
                .chain(next_players.iter())
                .cloned(),
        );
        let (output, _) = deal::<MinPk, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, dealers)
            .expect("trusted deal");
        let info = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(2),
            output,
            players,
            next_players,
            directory: addresses(&peers),
        };

        let decoded =
            EpochInfo::<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>>::decode_cfg(
                info.encode(),
                &(NZU32!(4), crate::dkg::tests::max_supported_mode()),
            )
            .expect("decode addressed epoch info");
        assert_eq!(decoded, info);
    }

    #[test]
    fn addressed_epoch_info_rejects_extra_directory_peer() {
        let mut info = addressed_info(1);
        info.directory = addresses(&keys(2));
        assert!(
            EpochInfo::<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>>::decode_cfg(
                info.encode(),
                &(NZU32!(1), crate::dkg::tests::max_supported_mode()),
            )
            .is_err()
        );
    }

    #[test]
    fn addressed_epoch_info_rejects_missing_directory_peer() {
        let mut info = addressed_info(1);
        info.directory = addresses(&keys(0));
        assert!(
            EpochInfo::<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>>::decode_cfg(
                info.encode(),
                &(NZU32!(1), crate::dkg::tests::max_supported_mode()),
            )
            .is_err()
        );
    }

    #[test]
    fn addressed_epoch_info_rejects_wrong_directory_peer() {
        let mut info = addressed_info(1);
        let wrong = Set::from_iter_dedup([ed25519::PrivateKey::from_seed(1).public_key()]);
        info.directory = addresses(&wrong);
        assert!(
            EpochInfo::<MinPk, ed25519::PublicKey, Addresses<ed25519::PublicKey>>::decode_cfg(
                info.encode(),
                &(NZU32!(1), crate::dkg::tests::max_supported_mode()),
            )
            .is_err()
        );
    }

    fn participants(count: u64) -> Participants<ed25519::PublicKey> {
        let keys = keys(count);
        Participants {
            dealers: keys.clone(),
            players: keys,
            next_players: Set::default(),
        }
    }

    #[test]
    fn epoch_capacity_rejects_insufficient_bootstrap_slots() {
        assert_eq!(
            participants(2).validate_epoch_capacity::<MinPk>(NZU64!(4), None),
            Err(EpochCapacityError {
                available: 1,
                required: 2,
            })
        );
    }

    #[test]
    fn epoch_capacity_accepts_exact_bootstrap_slots() {
        assert!(
            participants(2)
                .validate_epoch_capacity::<MinPk>(NZU64!(5), None)
                .is_ok()
        );
    }

    #[test]
    fn epoch_capacity_rejects_short_epoch_with_single_dealer() {
        assert_eq!(
            participants(1).validate_epoch_capacity::<MinPk>(NZU64!(3), None),
            Err(EpochCapacityError {
                available: 0,
                required: 1,
            })
        );
    }

    #[test]
    fn epoch_capacity_rejects_insufficient_reshare_slots() {
        let players = keys(4);
        let (previous, _) =
            deal::<MinPk, _, N3f1>(TestRng::new(0), Mode::NonZeroCounter, players.clone())
                .expect("trusted deal");

        assert_eq!(
            Participants {
                dealers: players.clone(),
                players,
                next_players: Set::default(),
            }
            .validate_epoch_capacity(NZU64!(6), Some(&previous)),
            Err(EpochCapacityError {
                available: 2,
                required: 3,
            })
        );
    }

    #[test]
    fn epoch_capacity_accepts_exact_reshare_slots() {
        let players = keys(4);
        let (previous, _) =
            deal::<MinPk, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, players.clone())
                .expect("trusted deal");

        assert!(
            Participants {
                dealers: players.clone(),
                players,
                next_players: Set::default(),
            }
            .validate_epoch_capacity(NZU64!(7), Some(&previous))
            .is_ok()
        );
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for Participants<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            dealers: u.arbitrary()?,
            players: u.arbitrary()?,
            next_players: u.arbitrary()?,
        })
    }
}

/// Canonical public epoch artifact.
///
/// This is the public truth needed to start an epoch: the latest public output,
/// the participant sets not already carried by that output, and the transport
/// [`Directory`] for every peer of the epoch. The genesis block carries the
/// [`EpochInfo`] for epoch 0; the final block of each epoch carries the
/// [`EpochInfo`] for the following epoch. The reshare actor never invents this;
/// it reads it back from finalized block ancestry.
///
/// Because the directory rides in the artifact, a node recovering through a
/// certificate-backed route (a finalized boundary block, a
/// [`probe`](crate::dkg::probe) artifact, or persisted
/// [`state_sync`](crate::dkg::state_sync) material) can activate the epoch's
/// peers without access to application state.
#[derive(Clone, Debug, PartialEq, Eq, EncodeSize, Write)]
pub struct EpochInfo<V: Variant, P: PublicKey, D: Directory<P> = Unit> {
    /// Whether or not the reshare ceremony in this epoch was successful.
    pub outcome: EpochOutcome,
    /// Epoch this artifact describes.
    pub epoch: Epoch,
    /// Latest public DKG output.
    pub output: Output<V, P>,
    /// Peers that receive shares in this epoch.
    pub players: Set<P>,
    /// Players of the next epoch, tracked early for connectivity.
    pub next_players: Set<P>,
    /// Transport directory containing exactly this epoch's dealers, players,
    /// and next players.
    pub directory: D,
}

impl<V: Variant, P: PublicKey, D: Directory<P>> EpochInfo<V, P, D> {
    /// Reconstructs the complete participant snapshot for this epoch.
    pub fn participants(&self) -> Participants<P> {
        Participants {
            dealers: self.output.players().clone(),
            players: self.players.clone(),
            next_players: self.next_players.clone(),
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Read for EpochInfo<V, P, D> {
    /// Maximum entries accepted in each participant set and maximum supported
    /// sharing mode version.
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(
        buf: &mut impl Buf,
        (max_participants, max_supported_mode): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let outcome = EpochOutcome::read(buf)?;
        let epoch = Epoch::read(buf)?;
        let output = Output::<V, P>::read_cfg(buf, &(*max_participants, *max_supported_mode))?;
        let players = Set::read_cfg(
            buf,
            &(RangeCfg::new(0..=max_participants.get() as usize), ()),
        )?;
        let next_players = Set::read_cfg(
            buf,
            &(RangeCfg::new(0..=max_participants.get() as usize), ()),
        )?;
        let peers = Set::from_iter_dedup(
            output
                .players()
                .iter()
                .chain(players.iter())
                .chain(next_players.iter())
                .cloned(),
        );
        let directory = D::read_cfg(buf, &D::codec_config(&peers))?;
        if !directory.matches(&peers) {
            return Err(CodecError::Invalid(
                "EpochInfo",
                "directory does not match participants",
            ));
        }
        Ok(Self {
            outcome,
            epoch,
            output,
            players,
            next_players,
            directory,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, P: PublicKey, D: Directory<P>> arbitrary::Arbitrary<'_> for EpochInfo<V, P, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    Output<V, P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            outcome: u.arbitrary()?,
            epoch: u.arbitrary()?,
            output: u.arbitrary()?,
            players: u.arbitrary()?,
            next_players: u.arbitrary()?,
            directory: u.arbitrary()?,
        })
    }
}

/// A public artifact published by the reshare actor into a block.
///
/// During the dealing and inclusion window of an epoch the actor publishes
/// finalized dealer logs. The final block of an epoch instead carries the
/// canonical [`EpochInfo`] for the following epoch.
#[allow(clippy::large_enum_variant)]
#[derive(EncodeSize, Write)]
pub enum Payload<V: Variant, C: Signer, D: Directory<C::PublicKey> = Unit> {
    /// A finalized signed dealer log for inclusion mid-epoch.
    #[codec(tag = 0)]
    DealerLog(SignedDealerLog<V, C>),
    /// The canonical public epoch artifact for the next epoch, carried by the
    /// final block of the current epoch.
    #[codec(tag = 1)]
    EpochInfo(EpochInfo<V, C::PublicKey, D>),
}

impl<V: Variant, C: Signer, D: Directory<C::PublicKey>> Clone for Payload<V, C, D> {
    fn clone(&self) -> Self {
        match self {
            Self::DealerLog(log) => Self::DealerLog(log.clone()),
            Self::EpochInfo(info) => Self::EpochInfo(info.clone()),
        }
    }
}

impl<V: Variant, C: Signer, D: Directory<C::PublicKey>> PartialEq for Payload<V, C, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DealerLog(a), Self::DealerLog(b)) => a == b,
            (Self::EpochInfo(a), Self::EpochInfo(b)) => a == b,
            _ => false,
        }
    }
}

impl<V: Variant, C: Signer, D: Directory<C::PublicKey>> Eq for Payload<V, C, D> {}

impl<V: Variant, C: Signer, D: Directory<C::PublicKey>> Read for Payload<V, C, D> {
    /// Maximum entries accepted in each participant set and maximum supported
    /// sharing mode version.
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::DealerLog(SignedDealerLog::read_cfg(reader, &cfg.0)?)),
            1 => Ok(Self::EpochInfo(EpochInfo::read_cfg(reader, cfg)?)),
            n => Err(CodecError::InvalidEnum(n)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, C: Signer, D: Directory<C::PublicKey>> arbitrary::Arbitrary<'_>
    for Payload<V, C, D>
where
    SignedDealerLog<V, C>: for<'a> arbitrary::Arbitrary<'a>,
    EpochInfo<V, C::PublicKey, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary::<bool>()? {
            Self::DealerLog(u.arbitrary()?)
        } else {
            Self::EpochInfo(u.arbitrary()?)
        })
    }
}

/// Wire message type for DKG protocol communication.
#[derive(EncodeSize, Read, Write)]
pub enum Message<V: Variant, P: PublicKey> {
    /// A dealer message containing public and private components for a player.
    #[codec(tag = 0)]
    Dealer(#[codec(cfg)] DealerPubMsg<V>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
    #[codec(tag = 1)]
    Ack(PlayerAck<P>),
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, P: PublicKey> arbitrary::Arbitrary<'_> for Message<V, P>
where
    DealerPubMsg<V>: for<'a> arbitrary::Arbitrary<'a>,
    PlayerAck<P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary::<bool>()? {
            Self::Dealer(u.arbitrary()?, u.arbitrary()?)
        } else {
            Self::Ack(u.arbitrary()?)
        })
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::dkg::network::Addresses;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};

    commonware_conformance::conformance_tests! {
        CodecConformance<EpochOutcome>,
        CodecConformance<Participants<ed25519::PublicKey>>,
        CodecConformance<EpochInfo<MinSig, ed25519::PublicKey>> => 8192,
        CodecConformance<EpochInfo<MinSig, ed25519::PublicKey, Addresses<ed25519::PublicKey>>> => 8192,
        CodecConformance<Payload<MinSig, ed25519::PrivateKey>> => 8192,
        CodecConformance<Payload<MinSig, ed25519::PrivateKey, Addresses<ed25519::PublicKey>>> => 8192,
        CodecConformance<Message<MinSig, ed25519::PublicKey>>,
    }
}
