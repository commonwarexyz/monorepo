use crate::bls12381::primitives::group::Element;
use crate::bls12381::primitives::poly;

pub fn public_hex(public: &poly::Public) -> String {
    hex::encode(poly::public(public).serialize())
}
