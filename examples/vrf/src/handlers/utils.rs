use commonware_codec::{EncodeSize, FixedSize, Encode};
use commonware_cryptography::bls12381::primitives::{group::Element, poly};
use commonware_utils::{hex, Array};

pub const ACK_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_ACK_";

/// Create a payload for acking a secret.
///
/// TODO: remove in favor of (round, dealer, commitment).encode()
pub fn payload<P: Array>(round: u64, dealer: &P, commitment: &poly::Public) -> Vec<u8> {
    let mut payload = Vec::with_capacity(u64::SIZE + P::SIZE + commitment.encode_size());
    (round, dealer, commitment).encode();
    payload
}

/// Convert a public polynomial to a hexadecimal representation of
/// the public key.
pub fn public_hex(public: &poly::Public) -> String {
    hex(&poly::public(public).serialize())
}
