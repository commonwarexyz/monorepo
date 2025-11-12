//! BLS12-381 threshold signature scheme for aggregation.

use crate::signing_scheme::bls12381_threshold as raw;
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_utils::set::Ordered;

/// BLS12-381 threshold signature scheme for aggregation.
#[derive(Clone, Debug)]
pub struct Bls12381Threshold<P: PublicKey, V: Variant> {
    /// Ordered set of participant public keys.
    pub participants: Ordered<P>,
    /// Raw BLS12-381 threshold implementation.
    pub raw: raw::Bls12381Threshold<V>,
}

impl<P: PublicKey, V: Variant> Bls12381Threshold<P, V> {
    /// Creates a new scheme with participants and the raw threshold implementation.
    pub fn new(
        participants: Ordered<P>,
        raw: raw::Bls12381Threshold<V>,
    ) -> Self {
        Self { participants, raw }
    }
}

use crate::aggregation::types::Item;

crate::impl_scheme_trait! {
    impl[P, V] Scheme for Bls12381Threshold<P, V>
    where [
        P: PublicKey,
        V: Variant + Send + Sync,
    ]
    {
        Context<'a, D> = [ &'a Item<D> ],
        PublicKey = P,
        Signature = V::Signature,
        Certificate = V::Signature,
        raw = raw,
        participants = participants,
        is_attributable = false,
        codec_config = (),
        codec_config_unbounded = (),
    }
}
