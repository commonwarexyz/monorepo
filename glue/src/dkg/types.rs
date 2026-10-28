//! Epoch artifacts, participant sets, and wire messages of the DKG protocol.

use crate::dkg::network::Directory;
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, MaxEncodeSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
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
use commonware_utils::{Widen, ordered::Set, sequence::Unit};
use std::num::NonZeroU32;
use thiserror::Error;

/// Returns the codec's participant cap for committees of at most `participants` members.
///
/// # Panics
///
/// Panics if `participants` is zero or exceeds `u32::MAX`.
pub(crate) fn max_participants(participants: usize) -> NonZeroU32 {
    u32::try_from(participants)
        .ok()
        .and_then(NonZeroU32::new)
        .expect("participants must be non-zero and fit in u32")
}

/// Material for an epoch-scoped threshold scheme and this node's role in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemeInfo<V: Variant, P: PublicKey> {
    /// Material for a verifier outside the committee.
    Verifier {
        /// Players of the epoch's threshold output.
        participants: Set<P>,
        /// Public group polynomial.
        sharing: Sharing<V>,
    },
    /// Material for a committee member without a signing share.
    Member {
        /// Players of the epoch's threshold output.
        participants: Set<P>,
        /// Public group polynomial.
        sharing: Sharing<V>,
        /// This node's identity key, one of `participants`.
        public_key: P,
    },
    /// Material for a committee member that also signs with `share`.
    Signer {
        /// Players of the epoch's threshold output.
        participants: Set<P>,
        /// Public group polynomial.
        sharing: Sharing<V>,
        /// This node's secret share.
        share: Share,
    },
}

impl<V: Variant, P: PublicKey> SchemeInfo<V, P> {
    /// Describes the scheme for the node identified by `public_key`: a signer when it holds
    /// `share`, a member when it is one of `participants` without a share, and a verifier
    /// otherwise.
    pub fn new(
        public_key: &P,
        participants: Set<P>,
        sharing: Sharing<V>,
        share: Option<Share>,
    ) -> Self {
        match share {
            Some(share) => Self::Signer {
                participants,
                sharing,
                share,
            },
            None if participants.position(public_key).is_some() => Self::Member {
                participants,
                sharing,
                public_key: public_key.clone(),
            },
            None => Self::Verifier {
                participants,
                sharing,
            },
        }
    }
}

/// Result of a DKG or reshare ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum EpochOutcome {
    /// The ceremony produced a new public output.
    Success,
    /// The ceremony failed, and the previous public output carries forward.
    Failure,
}

impl Write for EpochOutcome {
    fn write(&self, writer: &mut impl BufMut) {
        let tag = match self {
            Self::Success => 0u8,
            Self::Failure => 1u8,
        };
        tag.write(writer);
    }
}

impl FixedSize for EpochOutcome {
    const SIZE: usize = u8::SIZE;
}

impl Read for EpochOutcome {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Success),
            1 => Ok(Self::Failure),
            n => Err(CodecError::InvalidEnum(n)),
        }
    }
}

/// Participants for a DKG/reshare epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participants<P: PublicKey> {
    /// Peers that distribute dealings in this epoch.
    pub dealers: Set<P>,
    /// Peers that receive shares in this epoch.
    pub players: Set<P>,
    /// Players of the next epoch, tracked early for connectivity.
    pub next_players: Set<P>,
}

/// Reasons [`Participants::validate`] rejects a participant set.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParticipantsError {
    /// The dealer set is empty.
    #[error("dealers must not be empty")]
    EmptyDealers,
    /// The player set is empty.
    #[error("players must not be empty")]
    EmptyPlayers,
    /// A participant set (dealers, players, or next players) has `actual` members, more than
    /// `max`.
    #[error("too many participants: {actual} > {max}")]
    TooManyParticipants { actual: usize, max: usize },
    /// In reshare round zero, the dealers are not exactly the previous output's players.
    #[error("round-zero reshare dealers must equal previous output players")]
    InitialReshareDealers,
    /// In a later reshare round, a dealer is not one of the previous output's players.
    #[error("reshare dealer is not a previous player")]
    UnknownReshareDealer,
}

impl<P: PublicKey> Participants<P> {
    /// Returns the peers to activate for this epoch: the dealers as primary peers, and the
    /// players and next players as secondary peers.
    ///
    /// Dealers send the epoch's dealings. Players and next players are tracked for the
    /// connectivity needed to receive dealings and to prepare the next epoch.
    pub fn tracked_peers(&self) -> TrackedPeers<P> {
        TrackedPeers::new(
            self.dealers.clone(),
            Set::from_iter_dedup(self.players.iter().chain(self.next_players.iter()).cloned()),
        )
    }

    /// Checks that the participants are usable for `round`.
    ///
    /// Returns [`ParticipantsError::EmptyDealers`] or [`ParticipantsError::EmptyPlayers`]
    /// for an empty set, and [`ParticipantsError::TooManyParticipants`] if any set exceeds
    /// `max_participants`. With a `previous` output, round zero requires the dealers to
    /// equal its players ([`ParticipantsError::InitialReshareDealers`]), and later rounds
    /// require every dealer to be one of its players
    /// ([`ParticipantsError::UnknownReshareDealer`]). Returns `Ok(())` otherwise.
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
}

impl<P: PublicKey> Write for Participants<P> {
    fn write(&self, writer: &mut impl BufMut) {
        self.dealers.write(writer);
        self.players.write(writer);
        self.next_players.write(writer);
    }
}

impl<P: PublicKey> EncodeSize for Participants<P> {
    fn encode_size(&self) -> usize {
        self.dealers.encode_size() + self.players.encode_size() + self.next_players.encode_size()
    }
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
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt::deal,
            primitives::{sharing::Mode, variant::MinPk},
        },
        ed25519,
    };
    use commonware_p2p::Address;
    use commonware_utils::{N3f1, NZU32, TestRng};
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

    /// A node's role follows its share and its place among the players: a player with a share
    /// signs, a player without one is a member, and any other node is a verifier.
    #[test]
    fn scheme_info_names_the_node_role() {
        let keys = keys(4);
        let (output, shares) =
            deal::<MinPk, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, keys.clone())
                .expect("trusted deal must succeed");
        let sharing = output.public().clone();
        let player = keys
            .iter()
            .nth(1)
            .expect("keys must hold four players")
            .clone();
        let share = shares
            .get_value(&player)
            .cloned()
            .expect("player must hold a share");
        let outsider = ed25519::PrivateKey::from_seed(99).public_key();

        assert_eq!(
            SchemeInfo::new(&player, keys.clone(), sharing.clone(), Some(share.clone())),
            SchemeInfo::Signer {
                participants: keys.clone(),
                sharing: sharing.clone(),
                share,
            }
        );
        assert_eq!(
            SchemeInfo::new(&player, keys.clone(), sharing.clone(), None),
            SchemeInfo::Member {
                participants: keys.clone(),
                sharing: sharing.clone(),
                public_key: player,
            }
        );
        assert_eq!(
            SchemeInfo::new(&outsider, keys.clone(), sharing.clone(), None),
            SchemeInfo::Verifier {
                participants: keys,
                sharing,
            }
        );
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

/// The public description of an epoch.
///
/// It holds the epoch's threshold output, the participant sets that output does not
/// carry, and the transport [`Directory`] for every peer of the epoch. Genesis carries the
/// [`EpochInfo`] for epoch 0, and the final block of each epoch carries the [`EpochInfo`]
/// for the next. See [Peer Activation](crate::dkg#peer-activation) for how the directory is
/// used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInfo<V: Variant, P: PublicKey, D: Directory<P> = Unit> {
    /// Outcome of the ceremony that produced this artifact (on
    /// [`EpochOutcome::Failure`], `output` is the previous output carried forward).
    pub outcome: EpochOutcome,
    /// Epoch this artifact describes.
    pub epoch: Epoch,
    /// Public threshold output whose players are this epoch's dealers.
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
    /// Returns the largest encoded size of an artifact whose participant sets each hold at most
    /// `max_participants` participants.
    pub fn max_encode_size(max_participants: NonZeroU32) -> usize {
        let participants: usize = Widen::widen(max_participants.get());
        let set = Set::<P>::max_encode_size(participants);

        // The directory names the union of the output's players, the players, and the next
        // players.
        let directory = D::max_encode_size(3 * participants);
        Output::<V, P>::max_encode_size(max_participants)
            + EpochOutcome::MAX_ENCODE_SIZE
            + Epoch::MAX_ENCODE_SIZE
            + set * 2
            + directory
    }

    /// Returns the epoch's participants, with the output's players as dealers.
    pub fn participants(&self) -> Participants<P> {
        Participants {
            dealers: self.output.players().clone(),
            players: self.players.clone(),
            next_players: self.next_players.clone(),
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Write for EpochInfo<V, P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.outcome.write(buf);
        self.epoch.write(buf);
        self.output.write(buf);
        self.players.write(buf);
        self.next_players.write(buf);
        self.directory.write(buf);
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> EncodeSize for EpochInfo<V, P, D> {
    fn encode_size(&self) -> usize {
        self.outcome.encode_size()
            + self.epoch.encode_size()
            + self.output.encode_size()
            + self.players.encode_size()
            + self.next_players.encode_size()
            + self.directory.encode_size()
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

/// A public reshare artifact carried by an application block.
pub enum Payload<V: Variant, P: PublicKey, D: Directory<P> = Unit> {
    /// A signed dealer log, carried from the epoch midpoint up to, but not including, the
    /// final block.
    DealerLog(SignedDealerLog<V, P>),
    /// An epoch's [`EpochInfo`]: epoch zero's in genesis (and in a one-shot DKG's final
    /// block), and otherwise the next epoch's in the final block of the current epoch.
    EpochInfo(EpochInfo<V, P, D>),
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Clone for Payload<V, P, D> {
    fn clone(&self) -> Self {
        match self {
            Self::DealerLog(log) => Self::DealerLog(log.clone()),
            Self::EpochInfo(info) => Self::EpochInfo(info.clone()),
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> PartialEq for Payload<V, P, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DealerLog(a), Self::DealerLog(b)) => a == b,
            (Self::EpochInfo(a), Self::EpochInfo(b)) => a == b,
            _ => false,
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Eq for Payload<V, P, D> {}

impl<V: Variant, P: PublicKey, D: Directory<P>> Write for Payload<V, P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::DealerLog(log) => {
                0u8.write(writer);
                log.write(writer);
            }
            Self::EpochInfo(info) => {
                1u8.write(writer);
                info.write(writer);
            }
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> EncodeSize for Payload<V, P, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::DealerLog(log) => log.encode_size(),
            Self::EpochInfo(info) => info.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Payload<V, P, D> {
    /// Returns the largest encoded size of a payload for at most `max_participants` participants.
    pub fn max_encode_size(max_participants: NonZeroU32) -> usize {
        let log = SignedDealerLog::<V, P>::max_encode_size(max_participants);
        let info = EpochInfo::<V, P, D>::max_encode_size(max_participants);
        log.max(info) + u8::SIZE
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Read for Payload<V, P, D> {
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
impl<V: Variant, P: PublicKey, D: Directory<P>> arbitrary::Arbitrary<'_> for Payload<V, P, D>
where
    SignedDealerLog<V, P>: for<'a> arbitrary::Arbitrary<'a>,
    EpochInfo<V, P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary::<bool>()? {
            Self::DealerLog(u.arbitrary()?)
        } else {
            Self::EpochInfo(u.arbitrary()?)
        })
    }
}

/// Point-to-point message of a DKG or reshare ceremony.
pub enum Message<V: Variant, P: PublicKey> {
    /// A dealer's public and private messages for one player.
    Dealer(DealerPubMsg<V>, DealerPrivMsg),
    /// A player's acknowledgement to a dealer.
    Ack(PlayerAck<P>),
}

impl<V: Variant, P: PublicKey> Write for Message<V, P> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Dealer(pub_msg, priv_msg) => {
                0u8.write(writer);
                pub_msg.write(writer);
                priv_msg.write(writer);
            }
            Self::Ack(ack) => {
                1u8.write(writer);
                ack.write(writer);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Message<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(pub_msg, priv_msg) => pub_msg.encode_size() + priv_msg.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Message<V, P> {
    /// Returns the largest encoded size of a message for at most `max_participants` participants.
    pub fn max_encode_size(max_participants: NonZeroU32) -> usize {
        let dealer =
            DealerPubMsg::<V>::max_encode_size(max_participants) + DealerPrivMsg::MAX_ENCODE_SIZE;
        dealer.max(PlayerAck::<P>::MAX_ENCODE_SIZE) + u8::SIZE
    }
}

impl<V: Variant, P: PublicKey> Read for Message<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(reader)?;
        match tag {
            0 => {
                let pub_msg = DealerPubMsg::read_cfg(reader, cfg)?;
                let priv_msg = DealerPrivMsg::read(reader)?;
                Ok(Self::Dealer(pub_msg, priv_msg))
            }
            1 => {
                let ack = PlayerAck::read(reader)?;
                Ok(Self::Ack(ack))
            }
            n => Err(CodecError::InvalidEnum(n)),
        }
    }
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
        CodecConformance<Payload<MinSig, ed25519::PublicKey>> => 8192,
        CodecConformance<Payload<MinSig, ed25519::PublicKey, Addresses<ed25519::PublicKey>>> => 8192,
        CodecConformance<Message<MinSig, ed25519::PublicKey>>,
    }
}
