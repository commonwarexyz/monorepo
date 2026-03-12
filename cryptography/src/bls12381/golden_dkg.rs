#[allow(dead_code)]
mod evrf;

use super::dkg::Info;
use crate::bls12381::primitives::{group::Share, sharing::Sharing, variant::Variant};
use commonware_utils::ordered::Map;
pub use evrf::{PrivateKey, PublicKey};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

pub fn deal<V: Variant>(
    _rng: &mut impl CryptoRngCore,
    _info: &Info<V, PublicKey>,
    _me: &PrivateKey,
) -> SignedDealerLog {
    todo!()
}

pub fn observe<V: Variant>(_logs: BTreeMap<PublicKey, DealerLog>) -> Sharing<V> {
    todo!()
}

pub fn play<V: Variant>(
    _logs: BTreeMap<PublicKey, DealerLog>,
    _me: &PrivateKey,
) -> (Sharing<V>, Share) {
    todo!()
}

pub struct SignedDealerLog {}

impl SignedDealerLog {
    pub fn identify(self) -> Option<(PublicKey, DealerLog)> {
        todo!()
    }
}

pub struct DealerLog {}

impl DealerLog {
    #[allow(dead_code)]
    fn batch_check(
        _batch: impl IntoIterator<Item = (PublicKey, Self)>,
    ) -> Map<PublicKey, EncryptedShares> {
        todo!()
    }
}

struct EncryptedShares {}
