mod broadcast;
mod cyphered_share;
mod dealer;
mod error;
mod evrf;
mod registry;

#[cfg(test)]
mod test {
    use super::*;
    use crate::dealer::Dealer;
    use crate::evrf::EVRF;
    use commonware_cryptography::bls12381::primitives::{
        group::{Element, Scalar},
        variant::MinPk,
    };
    use rand::thread_rng;

    #[test]
    fn test_generation() {
        let beta = Scalar::one();
        let rng = &mut thread_rng();
        let evrf = EVRF::<MinPk>::random(rng, beta);
    }
}
