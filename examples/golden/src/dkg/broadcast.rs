use crate::dkg::ciphered_share::CipheredShare;
use crate::error::Error;
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadRangeExt, Write};
use commonware_cryptography::bls12381::primitives::group::{Element, Scalar, G1};
use commonware_cryptography::bls12381::primitives::poly;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_cryptography::bls12381::PublicKey;
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::{Committable, Digestible, Hasher, Sha256};
use commonware_utils::set::Ordered;
use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum BroadcastMsgError {
    #[error("Player public key not found {0}")]
    PlayerNotFound(u32),
    #[error("Insufficient amount of shares {0}")]
    UnexpectedShares(u32),
    #[error("Invalid ciphertext")]
    InvalidCipherText,
}
#[derive(Clone)]
pub struct BroadcastMsg {
    msg: Vec<u8>,
    shares: Vec<CipheredShare>,
    poly: poly::Public<MinPk>,
}

impl BroadcastMsg {
    const COMMITMENT_MSG: &[u8] = b"GOLDEN_DKG_SHARES";
    pub fn new(msg: Vec<u8>, shares: Vec<CipheredShare>, poly: poly::Public<MinPk>) -> Self {
        Self { msg, shares, poly }
    }

    /// Validation to be performed every time that a player receives a [`BroadcastMsg`] from a dealer
    /// This function covers steps 7-8-9 of Round1.
    /// If validation is successful, it returns the vector of share commitments
    pub fn validate(
        &self,
        dealer: u32,
        players: &Ordered<PublicKey>,
    ) -> Result<Vec<(u32, G1)>, Error> {
        let Some(dealer_pk) = players.get(dealer as usize) else {
            return Err(BroadcastMsgError::PlayerNotFound(dealer).into());
        };
        let num_players = players.len() as u32;
        let shares_len = self.shares.len() as u32;
        if shares_len != num_players {
            return Err(BroadcastMsgError::UnexpectedShares(shares_len).into());
        }

        let mut out = Vec::with_capacity(self.shares.len());

        for cs in &self.shares {
            let k = cs.index();
            let Some(receiver_pk) = players.get(k as usize) else {
                return Err(BroadcastMsgError::PlayerNotFound(k).into());
            };
            cs.verify_zk_proof(*dealer_pk.as_ref(), &self.msg, *receiver_pk.as_ref())?;

            let x_jk = self.verify_validity_of_ciphertext(cs, k)?;
            out.push((k, x_jk));
        }

        Ok(out)
    }

    pub fn take_ciphered_share(&mut self, player: u32) -> Option<CipheredShare> {
        let position = self.shares.iter().position(|x| x.index() == player)?;
        let out = self.shares.remove(position);
        Some(out)
    }

    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    pub fn commitment_omega(&self) -> G1 {
        self.poly.get(0)
    }

    /// Step (9)
    fn verify_validity_of_ciphertext(&self, cs: &CipheredShare, k: u32) -> Result<G1, Error> {
        let g_z = cs.commitment_ciphered_share();
        let mut r = cs.commitment_random_scalar();

        let x = self.compute_share_committment(k);
        r.add(&x);

        if g_z != r {
            return Err(BroadcastMsgError::InvalidCipherText.into());
        }

        Ok(x)
    }

    /// X_{j,k}
    fn compute_share_committment(&self, k: u32) -> G1 {
        let mut out = G1::zero();

        // Recall that polynomial always evaluates argument +1 in order to avoid revealing of the secret (intercept of polynomial)
        let k_plus_one = k + 1;
        for l in 0..self.poly.degree() + 1 {
            let mut coeff = self.poly.get(l);
            let sc = Scalar::from(k_plus_one.pow(l));
            coeff.mul(&sc);
            out.add(&coeff);
        }

        out
    }
}

impl EncodeSize for BroadcastMsg {
    fn encode_size(&self) -> usize {
        self.msg.encode_size() + self.shares.encode_size() + self.poly.encode_size()
    }
}

impl Read for BroadcastMsg {
    type Cfg = (RangeCfg<usize>, RangeCfg<usize>, usize);
    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let (msg_range, shares_range, poly_degree) = cfg;

        let msg = Vec::<u8>::read_range(buf, *msg_range)?;

        let shares = Vec::<CipheredShare>::read_cfg(buf, &(*shares_range, ()))?;

        let poly = poly::Public::<MinPk>::read_cfg(buf, poly_degree)?;

        Ok(Self { msg, shares, poly })
    }
}

impl Write for BroadcastMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.msg.write(buf);
        self.shares.write(buf);
        self.poly.write(buf);
    }
}

impl Committable for BroadcastMsg {
    type Commitment = Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(Self::COMMITMENT_MSG)
    }
}

impl Digestible for BroadcastMsg {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.msg)
    }
}
