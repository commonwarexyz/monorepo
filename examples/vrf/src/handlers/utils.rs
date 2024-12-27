use bytes::BufMut;
use commonware_cryptography::bls12381::primitives::{group::Element, poly};
use commonware_utils::hex;
use std::mem::size_of;

pub const SHARE_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_SHARE_";

/// Create a payload for sharing a secret.
///
/// This payload is used to verify that a particular dealer shared an
/// invalid secret during the DKG/Resharing procedure.
pub fn payload(round: u64, dealer: u32, share: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size_of::<u64>() + size_of::<u32>() + share.len());
    payload.put_u64(round);
    payload.put_u32(dealer);
    payload.extend_from_slice(share);
    payload
}

/// Convert a public polynomial to a hexadecimal representation of
/// the public key.
pub fn public_hex(public: &poly::Public) -> String {
    hex(&poly::public(public).serialize())
}
