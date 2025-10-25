use commonware_codec::Encode;
use commonware_cryptography::bls12381::{
    primitives::{
        group::{Element, Point, Scalar, DST, G1},
        ops::compute_public,
        variant::MinPk,
    },
    PublicKey,
};
use rand_core::CryptoRngCore;

#[derive(Eq, PartialEq, Debug)]
pub struct Output {
    pub scalar: Scalar,
    pub commitment: G1,
    pub zk_proof: (), // Optimization: the zk_proof should be per-share but per-broadcast-msg
}

#[derive(Clone)]
pub struct EVRF {
    sk_i: Scalar,
    pk_i: PublicKey,
    beta: Scalar,
}

impl EVRF {
    pub fn evaluate(&self, msg: &[u8], party_pki: &PublicKey) -> Output {
        // Reference: Figure 3 (page 19)
        //(0) -> skipping
        //(1), (2), (3)
        let k = self.gen_df_secret(party_pki);
        //(4), (6)
        let mut r = Self::compute_pad(b"PADDING_R1", msg, &k);
        //(5), (7)
        let r2 = Self::compute_pad(b"PADDING_R2", msg, &k);
        //(8)
        r.mul(&self.beta);
        r.add(&r2);

        let mut c = G1::one();
        c.mul(&r);

        Output {
            scalar: r,
            commitment: c,
            zk_proof: (),
        }
    }
    pub fn new(sk_i: Scalar, beta: Scalar) -> Self {
        let pk_i = PublicKey::from(compute_public::<MinPk>(&sk_i));
        Self { pk_i, sk_i, beta }
    }

    pub fn random<R: CryptoRngCore>(rng: &mut R, beta: Scalar) -> Self {
        Self::new(Scalar::from_rand(rng), beta)
    }

    pub fn pk_i(&self) -> &PublicKey {
        &self.pk_i
    }

    fn compute_pad(dst: DST, msg: &[u8], k: &Scalar) -> Scalar {
        let mut out = G1::zero();
        out.map(dst, msg);
        out.mul(k);
        // Internally calls blst_p*_compress, which returns the x coordinate with metadata encoding
        let r = out.encode();
        // Using map: read fails because first coordinate fails the blst_sk_check
        Scalar::map(&[], &r[..])
    }

    fn gen_df_secret(&self, party: &PublicKey) -> Scalar {
        let mut party: G1 = *party.as_ref();
        party.mul(&self.sk_i);
        let s = party;
        // Internally calls blst_p*_compress, which returns the x coordinate with metadata encoding
        let s = s.encode();
        // Using map: read fails because first coordinate fails the blst_sk_check
        Scalar::map(&[], &s[..])
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_df_secret() {
        let sender_sk = Scalar::from(42u32);

        let receiver_sk = Scalar::from(2u32);

        let sender_evrf = EVRF::new(sender_sk, Scalar::one());
        let sender_pk = &sender_evrf.pk_i;
        let receiver_evrf = EVRF::new(receiver_sk, Scalar::one());
        let receiver_pk = &receiver_evrf.pk_i;

        let msg = b"hello world";
        let secret1 = sender_evrf.evaluate(msg, receiver_pk);
        let secret2 = receiver_evrf.evaluate(msg, sender_pk);

        assert!(secret1 == secret2)
    }
}
