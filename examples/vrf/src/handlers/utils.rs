use commonware_codec::{EncodeSize, FixedSize, Write};
use commonware_cryptography::bls12381::primitives::poly;
use commonware_utils::Array;

pub const ACK_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_ACK_";

/// Create a payload for acking a secret.
pub fn payload<P: Array>(round: u64, dealer: &P, commitment: &poly::Public) -> Vec<u8> {
    let mut payload = Vec::with_capacity(u64::SIZE + P::SIZE + commitment.encode_size());
    round.write(&mut payload);
    dealer.write(&mut payload);
    commitment.write(&mut payload);
    payload
}
