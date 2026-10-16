//! Synthetic facts from which a Multimmit epoch starts.

use super::{BlockRef, CertificateId, ChainId, history::genesis_commitment};
use crate::{
    Epochable,
    types::{Epoch, Height},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

const GENESIS_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_GENESIS";
const GENESIS_VQC_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_GENESIS_VQC";

/// Errors returned while deriving synthetic epoch genesis facts.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenesisError {
    /// Genesis defines no producer chain.
    #[error("genesis must contain at least one chain")]
    ZeroChains,
    /// The chain count cannot be represented by chain identifiers.
    #[error("genesis chain count {0} exceeds u32::MAX")]
    TooManyChains(usize),
}

/// Returns chain `chain`'s synthetic genesis object for `epoch`: height zero, digest
/// `H(GENESIS, epoch, chain)`.
///
/// Binding the epoch makes every epoch's chains start from distinct objects, so headers of one
/// epoch can never extend another's.
pub fn genesis_ref<H: Hasher>(epoch: Epoch, chain: ChainId) -> BlockRef<H::Digest> {
    let digest = H::hash(&[
        GENESIS_NAMESPACE,
        epoch.encode().as_ref(),
        chain.encode().as_ref(),
    ]);
    BlockRef::new(chain, Height::zero(), digest)
}

/// Synthetic facts every validator of an epoch holds before any message: one genesis object per
/// producer chain, the genesis V-QC `Q_gen` of view zero (named by `H(GENESIS_VQC, epoch)`), and
/// the tips-history commitment `C(Q_gen)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochGenesis<D: Digest> {
    epoch: Epoch,
    vqc: CertificateId<D>,
    history: D,
    tips: Arc<[BlockRef<D>]>,
}

impl<D: Digest> EpochGenesis<D> {
    /// Derives the genesis facts of `epoch` over `chains` producer chains.
    pub fn new<H: Hasher<Digest = D>>(epoch: Epoch, chains: usize) -> Result<Self, GenesisError> {
        if chains == 0 {
            return Err(GenesisError::ZeroChains);
        }
        let count = u32::try_from(chains).map_err(|_| GenesisError::TooManyChains(chains))?;
        let tips: Arc<[BlockRef<D>]> = (0..count)
            .map(|chain| genesis_ref::<H>(epoch, ChainId::new(chain)))
            .collect();
        let vqc = CertificateId::new(H::hash(&[GENESIS_VQC_NAMESPACE, epoch.encode().as_ref()]));
        Ok(Self {
            epoch,
            vqc,
            history: genesis_commitment::<H>(epoch, &tips),
            tips,
        })
    }

    /// Returns the identifier of the genesis V-QC, the parent of every view-one V-QC.
    pub const fn vqc(&self) -> CertificateId<D> {
        self.vqc
    }

    /// Returns `C(Q_gen)`, the tips-history commitment a view-one leader block carries.
    pub const fn history(&self) -> D {
        self.history
    }

    /// Returns one synthetic height-zero object per producer chain, in chain order.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns the synthetic object of `chain`.
    pub fn tip(&self, chain: ChainId) -> Option<&BlockRef<D>> {
        self.tips.get(chain.index())
    }
}

impl<D: Digest> Epochable for EpochGenesis<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;

    #[test]
    fn genesis_objects_bind_epoch_and_chain() {
        let genesis = EpochGenesis::new::<Sha256>(Epoch::new(4), 3).unwrap();
        assert_eq!(genesis.epoch(), Epoch::new(4));
        assert_eq!(genesis.tips().len(), 3);
        for (index, tip) in genesis.tips().iter().enumerate() {
            let chain = ChainId::new(index as u32);
            assert_eq!(tip.chain(), chain);
            assert!(tip.height().is_zero());
            assert_eq!(*tip, genesis_ref::<Sha256>(Epoch::new(4), chain));
            assert_eq!(genesis.tip(chain), Some(tip));
        }
        assert_ne!(genesis.tips()[0].digest(), genesis.tips()[1].digest());

        let next = EpochGenesis::new::<Sha256>(Epoch::new(5), 3).unwrap();
        assert_ne!(next.tips()[0], genesis.tips()[0]);
        assert_ne!(next.vqc(), genesis.vqc());
        assert_ne!(next.history(), genesis.history());
        assert_ne!(genesis.vqc().get(), genesis.tips()[0].digest());
        assert_eq!(
            genesis.vqc().get(),
            Sha256::hash(&[GENESIS_VQC_NAMESPACE, Epoch::new(4).encode().as_ref()])
        );
    }

    #[test]
    fn rejects_unrepresentable_chain_counts() {
        assert_eq!(
            EpochGenesis::<<Sha256 as Hasher>::Digest>::new::<Sha256>(Epoch::new(4), 0)
                .unwrap_err(),
            GenesisError::ZeroChains
        );
    }
}
