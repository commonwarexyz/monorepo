use bytes::BufMut;
use commonware_cryptography::{
    bls12381::primitives::{group::Element, poly},
    Array,
};
use commonware_utils::{hex, SizedSerialize};

pub const ACK_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_ACK_";

/// Create a payload for acking a secret.
pub fn payload<P: Array>(round: u64, dealer: &P, commitment: &[u8]) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(u64::SERIALIZED_LEN + P::SERIALIZED_LEN + commitment.len());
    payload.put_u64(round);
    payload.extend_from_slice(dealer);
    payload.extend_from_slice(commitment);
    payload
}

/// Convert a public polynomial to a hexadecimal representation of
/// the public key.
pub fn public_hex(public: &poly::Public) -> String {
    hex(&poly::public(public).serialize())
}
