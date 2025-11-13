use crate::{
    ordered_broadcast::signing_scheme::bls12381_threshold::Bls12381Threshold,
    signing_scheme::{bls12381_threshold as raw, SchemeProvider},
    types::Epoch,
    Supervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::Variant},
    PublicKey,
};
use commonware_utils::set::Ordered;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct Validators<P: PublicKey, V: Variant> {
    validators: Vec<P>,
    validators_map: HashMap<P, u32>,
    scheme: Arc<Bls12381Threshold<P, V>>,
}

impl<P: PublicKey, V: Variant> Validators<P, V> {
    pub fn new(
        polynomial: Public<V>,
        shares: Vec<Share>,
        mut validators: Vec<P>,
        quorum: u32,
    ) -> Self {
        use commonware_cryptography::bls12381::{dkg::ops, primitives::poly};

        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        // Create the scheme
        let evaluated = ops::evaluate_all::<V>(&polynomial, validators.len() as u32);
        let identity = *poly::public::<V>(&polynomial);
        let raw_scheme =
            raw::Bls12381Threshold::<V>::new(identity, evaluated, shares[0].clone(), quorum);
        let scheme = Arc::new(Bls12381Threshold::new(
            Ordered::from_iter(validators.clone()),
            raw_scheme,
        ));

        Self {
            validators,
            validators_map,
            scheme,
        }
    }
}

impl<P: PublicKey, V: Variant> Supervisor for Validators<P, V> {
    type Index = Epoch;
    type PublicKey = P;

    fn participants(&self, _: Self::Index) -> Option<&[Self::PublicKey]> {
        Some(&self.validators)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.validators_map.get(candidate).cloned()
    }
}

impl<P: PublicKey, V: Variant> SchemeProvider for Validators<P, V> {
    type Scheme = Bls12381Threshold<P, V>;

    fn scheme(&self, _: Epoch) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}
