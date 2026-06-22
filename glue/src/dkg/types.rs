//! Shared types for the DKG module.

use crate::dkg::reshare::MAX_SUPPORTED_MODE;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Output, PlayerAck, SignedDealerLog},
        primitives::{group::Share, sharing::Sharing, variant::Variant},
    },
    PublicKey, Signer,
};
use commonware_p2p::TrackedPeers;
use commonware_utils::ordered::Set;
use std::num::NonZeroU32;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum EpochOutcome {
    /// The epoch produced a new public output.
    Success,
    /// The epoch failed and carried the previous public state forward.
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

impl EncodeSize for EpochOutcome {
    fn encode_size(&self) -> usize {
        1
    }
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
/// This is the public truth needed to start an epoch: the round, the latest
/// public output, and the participant sets not already carried by that output.
/// The genesis block carries the [`EpochInfo`] for epoch 0; the final block of
/// each epoch carries the [`EpochInfo`] for the following epoch. The reshare
/// actor never invents this; it reads it back from finalized block ancestry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInfo<V: Variant, P: PublicKey> {
    /// Whether or not the reshare ceremony in this epoch was successful.
    pub outcome: EpochOutcome,
    /// Epoch this artifact describes.
    pub epoch: Epoch,
    /// Reshare ceremony round for the epoch. Incremented on each [`EpochOutcome::Success`].
    pub round: u64,
    /// Latest public DKG output.
    pub output: Output<V, P>,
    /// Peers that receive shares in this epoch.
    pub players: Set<P>,
    /// Players of the next epoch, tracked early for connectivity.
    pub next_players: Set<P>,
}

impl<V: Variant, P: PublicKey> EpochInfo<V, P> {
    /// Reconstructs the complete participant snapshot for this epoch.
    pub fn participants(&self) -> Participants<P> {
        Participants {
            dealers: self.output.players().clone(),
            players: self.players.clone(),
            next_players: self.next_players.clone(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for EpochInfo<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.outcome.write(buf);
        self.epoch.write(buf);
        self.round.write(buf);
        self.output.write(buf);
        self.players.write(buf);
        self.next_players.write(buf);
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for EpochInfo<V, P> {
    fn encode_size(&self) -> usize {
        self.outcome.encode_size()
            + self.epoch.encode_size()
            + self.round.encode_size()
            + self.output.encode_size()
            + self.players.encode_size()
            + self.next_players.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Read for EpochInfo<V, P> {
    /// Maximum number of participants accepted in any single set.
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, max: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            outcome: EpochOutcome::read(buf)?,
            epoch: Epoch::read(buf)?,
            round: ReadExt::read(buf)?,
            output: Output::<V, P>::read_cfg(buf, &(*max, MAX_SUPPORTED_MODE))?,
            players: Set::read_cfg(buf, &(RangeCfg::new(0..=max.get() as usize), ()))?,
            next_players: Set::read_cfg(buf, &(RangeCfg::new(0..=max.get() as usize), ()))?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, P: PublicKey> arbitrary::Arbitrary<'_> for EpochInfo<V, P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    Output<V, P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            outcome: u.arbitrary()?,
            epoch: u.arbitrary()?,
            round: u.arbitrary()?,
            output: u.arbitrary()?,
            players: u.arbitrary()?,
            next_players: u.arbitrary()?,
        })
    }
}

/// A public artifact published by the reshare actor into a block.
///
/// During the dealing and inclusion window of an epoch the actor publishes
/// finalized dealer logs. The final block of an epoch instead carries the
/// canonical [`EpochInfo`] for the following epoch.
#[allow(clippy::large_enum_variant)]
pub enum Payload<V: Variant, C: Signer> {
    /// A finalized signed dealer log for inclusion mid-epoch.
    DealerLog(SignedDealerLog<V, C>),
    /// The canonical public epoch artifact for the next epoch, carried by the
    /// final block of the current epoch.
    EpochInfo(EpochInfo<V, C::PublicKey>),
}

impl<V: Variant, C: Signer> Clone for Payload<V, C> {
    fn clone(&self) -> Self {
        match self {
            Self::DealerLog(log) => Self::DealerLog(log.clone()),
            Self::EpochInfo(info) => Self::EpochInfo(info.clone()),
        }
    }
}

impl<V: Variant, C: Signer> PartialEq for Payload<V, C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DealerLog(a), Self::DealerLog(b)) => a == b,
            (Self::EpochInfo(a), Self::EpochInfo(b)) => a == b,
            _ => false,
        }
    }
}

impl<V: Variant, C: Signer> Eq for Payload<V, C> {}

impl<V: Variant, C: Signer> Write for Payload<V, C> {
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

impl<V: Variant, C: Signer> EncodeSize for Payload<V, C> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::DealerLog(log) => log.encode_size(),
            Self::EpochInfo(info) => info.encode_size(),
        }
    }
}

impl<V: Variant, C: Signer> Read for Payload<V, C> {
    /// Maximum number of participants accepted in decoded artifacts.
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, max: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::DealerLog(SignedDealerLog::read_cfg(reader, max)?)),
            1 => Ok(Self::EpochInfo(EpochInfo::read_cfg(reader, max)?)),
            n => Err(CodecError::InvalidEnum(n)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, C: Signer> arbitrary::Arbitrary<'_> for Payload<V, C>
where
    SignedDealerLog<V, C>: for<'a> arbitrary::Arbitrary<'a>,
    EpochInfo<V, C::PublicKey>: for<'a> arbitrary::Arbitrary<'a>,
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
pub enum Message<V: Variant, P: PublicKey> {
    /// A dealer message containing public and private components for a player.
    Dealer(DealerPubMsg<V>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
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
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};

    commonware_conformance::conformance_tests! {
        CodecConformance<EpochOutcome>,
        CodecConformance<Participants<ed25519::PublicKey>>,
        CodecConformance<EpochInfo<MinSig, ed25519::PublicKey>> => 8192,
        CodecConformance<Payload<MinSig, ed25519::PrivateKey>> => 8192,
        CodecConformance<Message<MinSig, ed25519::PublicKey>>,
    }
}
