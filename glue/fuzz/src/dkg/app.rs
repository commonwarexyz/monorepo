//! The block of the reshare chain and the correct application.
//!
//! The chain carries no state beyond what the DKG module needs: a block is its
//! consensus context, its parent, its height, and at most one reshare payload.
//!
//! The correct application is a pure function of what it is given. It builds a
//! block around the payload the [`reshare::Application`] wrapper selected and
//! accepts every block: the wrapper checks payload placement and the final
//! block's epoch information before the application is asked.

use super::{
    COMMITTEE, Digest, Info, MockGroup, PublicKey, scheme::Scheme, stack::MAX_SUPPORTED_MODE,
};
use crate::stateful::runner::unattributed;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, MaxEncodeSize, Read, ReadExt as _,
    Write,
};
use commonware_consensus::{
    Application, Block as ConsensusBlock, BoundedBlock, CertifiableBlock, Heightable,
    marshal::ancestry::Ancestry,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digested, Digestible, Hasher, Sha256, bls12381::primitives::sharing::ModeVersion,
    ed25519,
};
use commonware_glue::dkg::{ReshareBlock, reshare, types::Payload};
use commonware_runtime::BufMut;
use commonware_utils::sequence::Unit;
use std::num::NonZeroU32;

/// The reshare payload a block of the chain may carry.
pub(super) type BlockPayload = Payload<MockGroup, PublicKey>;

/// The consensus context embedded in every block.
pub(super) type BlockContext = Context<Digest, PublicKey>;

/// What the [`reshare::Application`] wrapper hands the application for each
/// proposal: the payload it selected for the block.
pub(super) type Input = reshare::Input<(), MockGroup, ed25519::PrivateKey>;

/// Codec configuration of a block: the largest participant set a payload may
/// name and the newest sharing mode version it may use.
pub(super) const BLOCK_CFG: (NonZeroU32, ModeVersion) = (COMMITTEE, MAX_SUPPORTED_MODE);

/// A block of the reshare chain.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Block {
    context: BlockContext,
    parent: Digest,
    height: Height,
    payload: Option<BlockPayload>,
}

impl Block {
    /// The block at `height` extending `parent` that carries `payload`.
    pub(super) const fn new(
        context: BlockContext,
        parent: Digest,
        height: Height,
        payload: Option<BlockPayload>,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            payload,
        }
    }

    /// The height-zero block, which carries the description of epoch zero.
    pub(super) fn genesis(leader: PublicKey, info: Info) -> Self {
        Self::new(
            Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Digest::EMPTY),
            },
            Digest::EMPTY,
            Height::zero(),
            Some(Payload::EpochInfo(info)),
        )
    }

    /// This block with its digest.
    pub(super) fn digested(self) -> Digested<Self> {
        let digest = self.digest();
        Digested::precomputed(self, digest)
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl Read for Block {
    /// The largest participant set a payload may name and the newest sharing
    /// mode version it may use.
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let context = Context::read(buf)?;
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Option::<BlockPayload>::read_cfg(buf, cfg)?;
        Ok(Self::new(context, parent, height, payload))
    }
}

impl BoundedBlock for Block {
    fn max_encode_size((participants, _): &Self::Cfg) -> usize {
        BlockContext::MAX_ENCODE_SIZE
            + Digest::SIZE
            + Height::MAX_ENCODE_SIZE
            + bool::SIZE
            + BlockPayload::max_encode_size(*participants)
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = BlockContext;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl ReshareBlock for Block {
    type Variant = MockGroup;
    type PublicKey = PublicKey;
    type Directory = Unit;

    fn payload(&self) -> Option<BlockPayload> {
        self.payload.clone()
    }
}

/// The correct application.
///
/// It holds no state, so every clone, and every correct node, computes the
/// same block from the same context, parent, and payload.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct App;

impl<E: Send> Application<E> for App {
    type SigningScheme = Scheme;
    type Context = BlockContext;
    type Block = Block;
    type Input = Input;

    async fn propose(
        &mut self,
        (_, context): (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        let parent = ancestry.peek()?;
        let (parent, height) = (parent.digest(), parent.height().next());

        // The application is called inside an engine's task and is the
        // harness's code, not the engine's.
        Some(unattributed(|| {
            Block::new(context, parent, height, input.payload).digested()
        }))
    }

    async fn verify(&mut self, _: (E, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{fixtures::described, signers};
    use commonware_codec::Decode as _;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::Signer as _;

    fn info() -> Info {
        described(3, Epoch::zero()).0
    }

    #[test]
    fn block_roundtrips_and_stays_within_its_bound() {
        let leader = signers(1)[0].public_key();
        let genesis = Block::genesis(leader, info());
        let encoded = genesis.encode();
        assert!(encoded.len() <= Block::max_encode_size(&BLOCK_CFG));
        let decoded = Block::decode_cfg(encoded, &BLOCK_CFG).expect("a block must decode");
        assert!(decoded == genesis);
        assert_eq!(decoded.digest(), genesis.digest());

        let child = Block::new(
            genesis.context(),
            genesis.digest(),
            genesis.height().next(),
            None,
        );
        let decoded = Block::decode_cfg(child.encode(), &BLOCK_CFG).expect("a block must decode");
        assert!(decoded == child);
        assert_ne!(child.digest(), genesis.digest());
    }

    #[test]
    fn genesis_carries_epoch_zero() {
        let info = info();
        let genesis = Block::genesis(signers(1)[0].public_key(), info.clone());
        assert!(genesis.payload() == Some(Payload::EpochInfo(info)));
        assert_eq!(genesis.height(), Height::zero());
    }
}
