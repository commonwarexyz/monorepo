use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::{Element, Point, Scalar, DST},
    ops::compute_public,
    variant::Variant,
};
use rand_core::CryptoRngCore;

#[derive(Eq, PartialEq)]
pub struct Output<V: Variant> {
    pub scalar: Scalar,
    pub commitment: V::Public,
    pub zk_proof: (), // Optimization: the zk_proof should be per-share but per-broadcast-msg
}
pub struct EVRF<V: Variant> {
    sk_i: Scalar,
    pk_i: V::Public,
    beta: Scalar,
}

impl<V: Variant> EVRF<V> {
    pub fn new(sk_i: Scalar, beta: Scalar) -> Self {
        Self {
            pk_i: compute_public::<V>(&sk_i),
            sk_i,
            beta,
        }
    }

    pub fn random<R: CryptoRngCore>(rng: &mut R, beta: Scalar) -> Self {
        Self::new(Scalar::from_rand(rng), beta)
    }

    pub fn evaluate(&self, msg: &[u8], party_pki: V::Public) -> Output<V> {
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

        let mut c = V::Public::one();
        c.mul(&r);

        Output {
            scalar: r,
            commitment: c,
            zk_proof: (),
        }
    }

    fn compute_pad(dst: DST, msg: &[u8], k: &Scalar) -> Scalar {
        let mut out = V::Public::zero();
        out.map(dst, msg);
        out.mul(k);
        // Internally calls blst_p*_compress, which returns the x coordinate with metadata encoding
        let r = out.encode();
        // Using map: read fails because first coordinate fails the blst_sk_check
        Scalar::map(&[], &r[..])
    }

    fn gen_df_secret(&self, mut party: V::Public) -> Scalar {
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
    use commonware_cryptography::bls12381::primitives::{
        ops::compute_public,
        variant::{MinPk, MinSig},
    };

    use super::*;

    fn secret_random_match<V: Variant>() -> bool {
        let sender_sk = Scalar::from(42u32);
        let sender_pk = compute_public::<V>(&sender_sk);

        let receiver_sk = Scalar::from(2u32);
        let receiver_pk = compute_public::<V>(&receiver_sk);

        let sender_evrf = EVRF::<V>::new(sender_sk, Scalar::one());
        let receiver_evrf = EVRF::<V>::new(receiver_sk, Scalar::one());

        let msg = b"hello world";
        let secret1 = sender_evrf.evaluate(msg, receiver_pk);
        let secret2 = receiver_evrf.evaluate(msg, sender_pk);

        secret1 == secret2
    }

    #[test]
    fn test_df_secret() {
        let out = secret_random_match::<MinPk>();
        assert!(out);
        let out = secret_random_match::<MinSig>();
        assert!(out);
    }
}
