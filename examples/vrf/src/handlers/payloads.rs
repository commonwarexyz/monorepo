pub const SHARE_NAMESPACE: &[u8] = b"_COMMONWARE_DKG_SHARE_";

pub fn share(round: u64, dealer: u32, share: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&round.to_be_bytes());
    payload.extend_from_slice(&dealer.to_be_bytes());
    payload.extend_from_slice(share);
    payload
}
