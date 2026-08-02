//! Synthetic facts from which a Multimmit epoch starts.

use super::{BlockRef, CertificateId, ChainId, Height};
use crate::{Epochable, multimmit::config::CodecConfig, types::Epoch};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::Digest;

/// Errors returned while constructing synthetic epoch genesis facts.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenesisError {
    /// Genesis defines no producer chain.
    #[error("genesis must contain at least one chain tip")]
    EmptyTips,
    /// The number of tips cannot be represented by chain identifiers.
    #[error("genesis tip count {0} exceeds u32::MAX")]
    TooManyTips(usize),
    /// A tip is not in canonical chain order.
    #[error("tip {index} names chain {actual}, expected chain {expected}")]
    UnexpectedChain {
        /// The tip's position in the ordered vector.
        index: usize,
        /// The chain required at this position.
        expected: ChainId,
        /// The chain supplied at this position.
        actual: ChainId,
    },
    /// A synthetic genesis tip is not at height zero.
    #[error("genesis tip for chain {chain} is at non-zero height {height}")]
    NonZeroTip {
        /// The chain containing the invalid tip.
        chain: ChainId,
        /// The supplied chain height.
        height: Height,
    },
}

/// Synthetic per-chain and leader-chain facts for one epoch.
///
/// The attached deployment supplies opaque digests for the distinguished
/// leader and certificate facts. Multimmit validates only the epoch context
/// and canonical height-zero chain coordinates needed by the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochGenesis<D: Digest> {
    epoch: Epoch,
    leader: D,
    vqc: CertificateId<D>,
    lqc: CertificateId<D>,
    tips: Vec<BlockRef<D>>,
}

impl<D: Digest> EpochGenesis<D> {
    /// Creates checked synthetic genesis facts.
    pub fn new(
        epoch: Epoch,
        leader: D,
        vqc: CertificateId<D>,
        lqc: CertificateId<D>,
        tips: Vec<BlockRef<D>>,
    ) -> Result<Self, GenesisError> {
        validate_tips(&tips)?;

        Ok(Self {
            epoch,
            leader,
            vqc,
            lqc,
            tips,
        })
    }

    /// Returns the epoch initialized by these facts.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the distinguished view-zero leader digest.
    pub const fn leader(&self) -> D {
        self.leader
    }

    /// Returns the distinguished genesis V-QC identifier.
    pub const fn vqc(&self) -> CertificateId<D> {
        self.vqc
    }

    /// Returns the distinguished genesis L-QC identifier.
    pub const fn lqc(&self) -> CertificateId<D> {
        self.lqc
    }

    /// Returns one synthetic height-zero tip for every producer chain.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns the synthetic tip for `chain`.
    pub fn tip(&self, chain: ChainId) -> Option<&BlockRef<D>> {
        self.tips.get(chain.get() as usize)
    }
}

impl<D: Digest> Epochable for EpochGenesis<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<D: Digest> Read for EpochGenesis<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let leader = D::read(buf)?;
        let vqc = CertificateId::read(buf)?;
        let lqc = CertificateId::read(buf)?;
        let tips = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(cfg.chains()), ()))?;

        Self::new(epoch, leader, vqc, lqc, tips).map_err(|_| {
            CodecError::Invalid(
                "consensus::multimmit::EpochGenesis",
                "invalid canonical genesis tips",
            )
        })
    }
}

impl<D: Digest> Write for EpochGenesis<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.leader.write(buf);
        self.vqc.write(buf);
        self.lqc.write(buf);
        self.tips.write(buf);
    }
}

impl<D: Digest> EncodeSize for EpochGenesis<D> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.leader.encode_size()
            + self.vqc.encode_size()
            + self.lqc.encode_size()
            + self.tips.encode_size()
    }
}

fn validate_tips<D: Digest>(tips: &[BlockRef<D>]) -> Result<(), GenesisError> {
    if tips.is_empty() {
        return Err(GenesisError::EmptyTips);
    }
    if u32::try_from(tips.len()).is_err() {
        return Err(GenesisError::TooManyTips(tips.len()));
    }

    for (index, tip) in tips.iter().enumerate() {
        let expected = ChainId::new(index as u32);
        if tip.chain() != expected {
            return Err(GenesisError::UnexpectedChain {
                index,
                expected,
                actual: tip.chain(),
            });
        }
        if !tip.height().is_zero() {
            return Err(GenesisError::NonZeroTip {
                chain: tip.chain(),
                height: tip.height(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{config::Limits, types::Height};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    fn tips(chains: u32) -> Vec<BlockRef<Sha256Digest>> {
        (0..chains)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    Sha256::hash(&[&chain.to_be_bytes()]),
                )
            })
            .collect()
    }

    fn genesis(chains: u32) -> EpochGenesis<Sha256Digest> {
        EpochGenesis::new(
            Epoch::new(4),
            Sha256::hash(&[b"leader genesis"]),
            CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
            CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
            tips(chains),
        )
        .unwrap()
    }

    #[test]
    fn requires_non_empty_height_zero_tips_in_chain_order() {
        assert_eq!(
            EpochGenesis::new(
                Epoch::new(4),
                Sha256::hash(&[b"leader genesis"]),
                CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
                CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
                Vec::new(),
            )
            .unwrap_err(),
            GenesisError::EmptyTips
        );

        let mut duplicate = tips(2);
        duplicate[1] = BlockRef::new(
            ChainId::new(0),
            Height::zero(),
            Sha256::hash(&[b"duplicate"]),
        );
        assert!(matches!(
            EpochGenesis::new(
                Epoch::new(4),
                Sha256::hash(&[b"leader genesis"]),
                CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
                CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
                duplicate,
            ),
            Err(GenesisError::UnexpectedChain { index: 1, .. })
        ));

        let mut out_of_order = tips(2);
        out_of_order.swap(0, 1);
        assert!(matches!(
            EpochGenesis::new(
                Epoch::new(4),
                Sha256::hash(&[b"leader genesis"]),
                CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
                CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
                out_of_order,
            ),
            Err(GenesisError::UnexpectedChain { index: 0, .. })
        ));

        let non_zero = vec![BlockRef::new(
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"non-zero"]),
        )];
        assert_eq!(
            EpochGenesis::new(
                Epoch::new(4),
                Sha256::hash(&[b"leader genesis"]),
                CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
                CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
                non_zero,
            )
            .unwrap_err(),
            GenesisError::NonZeroTip {
                chain: ChainId::new(0),
                height: Height::new(1),
            }
        );
    }

    #[test]
    fn codec_round_trips_with_exact_chain_bound() {
        let genesis = genesis(3);
        let codec = CodecConfig::new(3, 3, Limits::new(4, 0).unwrap()).unwrap();
        assert_eq!(
            EpochGenesis::decode_cfg(genesis.encode(), &codec).unwrap(),
            genesis
        );

        let wrong_bound = CodecConfig::new(2, 2, Limits::new(4, 0).unwrap()).unwrap();
        assert!(EpochGenesis::<Sha256Digest>::decode_cfg(genesis.encode(), &wrong_bound).is_err());
    }
}
