use crate::{Hash, Height, View};
use bytes::Bytes;

pub const PROPOSAL_SUFFIX: &[u8] = b"_PROPOSAL";
pub const VOTE_SUFFIX: &[u8] = b"_VOTE";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

// TODO: hash all external context, union with payload_hash, and then hash that for block hash
pub fn proposal_digest(view: View, height: Height, parent: &Hash, payload_hash: &Hash) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(parent);
    msg.extend_from_slice(payload_hash);
    msg.into()
}

pub fn vote_digest(view: crate::View, height: Height, proposal_hash: Option<Hash>) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    if let Some(hash) = proposal_hash {
        msg.extend_from_slice(&hash);
    }
    msg.into()
}

pub fn finalize_digest(view: crate::View, height: Height, proposal_hash: &Hash) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(proposal_hash);
    msg.into()
}
