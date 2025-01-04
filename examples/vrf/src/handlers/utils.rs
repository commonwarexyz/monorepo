use bytes::BufMut;
use commonware_cryptography::{
    bls12381::primitives::{group::Element, poly},
    PublicKey,
};
use commonware_utils::hex;
use std::mem::size_of;

pub const ACK_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_ACK_";

/// Create a payload for sharing a secret.
///
/// This payload is used to verify that a particular dealer shared an
/// invalid secret during the DKG/Resharing procedure.
pub fn payload(round: u64, dealer: &PublicKey, share: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size_of::<u64>() + dealer.len() + share.len());
    payload.put_u64(round);
    payload.extend_from_slice(dealer);
    payload.extend_from_slice(share);
    payload
}

/// Convert a public polynomial to a hexadecimal representation of
/// the public key.
pub fn public_hex(public: &poly::Public) -> String {
    hex(&poly::public(public).serialize())
}
