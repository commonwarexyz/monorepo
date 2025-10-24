use crate::evrf::Output;
use commonware_cryptography::bls12381::primitives::{
    group::{Element, Scalar, Share as DKGShare},
    variant::Variant,
};
use std::cmp::Ord;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum ShareError {
    #[error("Invalid eVRF scalar")]
    InvalidEVRFScalar,
    #[error("nvalid zk proof")]
    InvalidZkProof,
}

#[derive(Eq, PartialEq)]
pub struct CypheredShare<V: Variant> {
    cyphered: DKGShare,
    commitment_r: V::Public,
    zk_proof: (),
}

impl<V: Variant> PartialOrd for CypheredShare<V> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index().partial_cmp(&other.index())
    }
}

impl<V: Variant> Ord for CypheredShare<V> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index().cmp(&other.index())
    }
}

impl<V: Variant> CypheredShare<V> {
    pub fn new(mut dkg_share: DKGShare, evrf: Output<V>) -> Self {
        let alpha = evrf.scalar;
        let commitment = evrf.commitment;
        let zk_proof = evrf.zk_proof;
        dkg_share.private.add(&alpha); // now the share is cyphered
        Self {
            cyphered: dkg_share,
            commitment_r: commitment,
            zk_proof,
        }
    }

    pub fn index(&self) -> u32 {
        self.cyphered.index
    }

    pub fn decrypt(mut self, evrf_scalar: Scalar) -> Result<Scalar, ShareError> {
        let mut g = V::Public::one();
        g.mul(&evrf_scalar);
        if g != self.commitment_r {
            return Err(ShareError::InvalidEVRFScalar);
        }
        self.cyphered.private.sub(&evrf_scalar);
        Ok(self.cyphered.private)
    }

    pub fn verify_zk_proof(
        &self,
        dealer: V::Public,
        msg: &[u8],
        receiver: V::Public,
    ) -> Result<(), ShareError> {
        // TODO: implement ZK-proof validation (figure 3, execpt last step)
        Err(ShareError::InvalidZkProof)
    }

    /// R_{j,k} = g^{r_{j,k}}
    pub fn commitment_random_scalar(&self) -> V::Public {
        self.commitment_r
    }

    /// g^{z_{j,k}}
    pub fn commitment_cyphered_share(&self) -> V::Public {
        let mut out = V::Public::one();
        out.mul(&self.cyphered.private);
        out
    }
}
