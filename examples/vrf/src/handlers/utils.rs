use commonware_cryptography::bls12381::primitives::{group::Element, poly};

/// Convert a public polynomial to a hexadecimal representation of
/// the public key.
pub fn public_hex(public: &poly::Public) -> String {
    hex::encode(poly::public(public).serialize())
}
