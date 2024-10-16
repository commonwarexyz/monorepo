use crate::{Hash, Height, View};
use bytes::Bytes;

pub const PROPOSAL_SUFFIX: &[u8] = b"_PROPOSAL";
pub const VOTE_SUFFIX: &[u8] = b"_VOTE";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn header_digest(height: Height, parent: &Hash) -> Bytes {
    let mut msg = Vec::with_capacity(8 + parent.len());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(parent);
    msg.into()
}

pub fn proposal_digest(view: View, header: &Hash, payload: &Hash) -> Bytes {
    let mut msg = Vec::with_capacity(8 + header.len() + payload.len());
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(header);
    msg.extend_from_slice(payload);
    msg.into()
}

pub fn vote_digest(view: View, height: Height, proposal_hash: Option<&Hash>) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + proposal_hash.map_or(0, |hash| hash.len()));
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    if let Some(hash) = proposal_hash {
        msg.extend_from_slice(hash);
    }
    msg.into()
}

pub fn finalize_digest(view: View, height: Height, proposal_hash: &Hash) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + proposal_hash.len());
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(proposal_hash);
    msg.into()
}
