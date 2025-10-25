use crate::participant::evrf::Output;
use commonware_cryptography::bls12381::primitives::group::{
    Element, Scalar, Share as DKGShare, G1,
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

#[derive(Eq, PartialEq, Clone)]
pub struct CipheredShare {
    ciphered: DKGShare,
    commitment_r: G1,
    zk_proof: (),
}

impl PartialOrd for CipheredShare {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CipheredShare {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index().cmp(&other.index())
    }
}

impl CipheredShare {
    pub fn new(mut dkg_share: DKGShare, evrf: Output) -> Self {
        let alpha = evrf.scalar;
        let commitment = evrf.commitment;
        // let zk_proof = evrf.zk_proof;
        let zk_proof = ();
        dkg_share.private.add(&alpha); // now the share is ciphered
        Self {
            ciphered: dkg_share,
            commitment_r: commitment,
            zk_proof,
        }
    }

    pub fn index(&self) -> u32 {
        self.ciphered.index
    }

    pub fn decrypt(mut self, evrf_scalar: Scalar) -> Result<Scalar, ShareError> {
        let mut g = G1::one();
        g.mul(&evrf_scalar);
        if g != self.commitment_r {
            return Err(ShareError::InvalidEVRFScalar);
        }
        self.ciphered.private.sub(&evrf_scalar);
        Ok(self.ciphered.private)
    }

    pub fn verify_zk_proof(
        &self,
        _dealer: G1,
        _msg: &[u8],
        _receiver: G1,
    ) -> Result<(), ShareError> {
        // TODO: implement ZK-proof validation (figure 3, execpt last step)
        // Err(ShareError::InvalidZkProof)
        Ok(())
    }

    /// R_{j,k} = g^{r_{j,k}}
    pub fn commitment_random_scalar(&self) -> G1 {
        self.commitment_r
    }

    /// g^{z_{j,k}}
    pub fn commitment_ciphered_share(&self) -> G1 {
        let mut out = G1::one();
        out.mul(&self.ciphered.private);
        out
    }
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::bls12381::{
        dkg::ops::generate_shares, primitives::variant::MinPk,
    };
    use commonware_utils::quorum;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_commiemtnet_ciphered() {
        let rng = &mut thread_rng();

        let n = 3;
        let t = quorum(n);
        let (_, shares) = generate_shares::<_, MinPk>(rng, None, n, t);

        let k = 0;

        // Random scalalr
        let alpha = Scalar::from_rand(rng);

        // Unciphered share
        let f_jk = shares[k].private.clone();

        // Ciphered share
        let mut z_jk = f_jk.clone();
        z_jk.add(&alpha);

        // Commitment random scalar
        let mut r_jk = G1::one();
        r_jk.mul(&alpha);

        // Commitment secret
        let mut big_f_jk = G1::one();
        big_f_jk.mul(&f_jk);

        // Commitment ciphered share
        big_f_jk.add(&r_jk);

        // Comitment secret
        let mut x_jk = G1::one();
        x_jk.mul(&z_jk);

        debug_assert_eq!(x_jk, big_f_jk)
    }

    #[test]
    fn test_commiemtnet_ciphered_from_poly() {
        let rng = &mut thread_rng();

        let n = 3;
        let t = quorum(n);
        let (poly, shares) = generate_shares::<_, MinPk>(rng, None, n, t);

        let k = 0;

        // Random scalalr
        let alpha = Scalar::from_rand(rng);

        // Unciphered share
        let f_jk = shares[k].private.clone();

        // Commitment secret
        let mut big_f_jk = G1::one();
        big_f_jk.mul(&f_jk);

        // Ciphered share
        let mut z_jk = f_jk;
        z_jk.add(&alpha);

        // Commitment random scalar
        let mut r_jk = G1::one();
        r_jk.mul(&alpha);

        let mut recov_x_jk = G1::zero();

        // Recall that polynomial always evaluates argument +1 in order to avoid revealing of the secret
        let k = k as u32 + 1;
        for l in 0..poly.degree() + 1 {
            let mut coeff = poly.get(l);
            let sc = Scalar::from(k.pow(l));
            coeff.mul(&sc);
            recov_x_jk.add(&coeff);
        }

        // Commitment ciphered share
        recov_x_jk.add(&r_jk);

        // Comitment secret
        let mut x_jk = G1::one();
        x_jk.mul(&z_jk);

        debug_assert_eq!(x_jk, recov_x_jk)
    }
}
