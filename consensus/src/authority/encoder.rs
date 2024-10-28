use super::{Height, View};
use bytes::Bytes;
use commonware_cryptography::Digest;
use commonware_utils::union;

pub const PROPOSAL_SUFFIX: &[u8] = b"_PROPOSAL";
pub const VOTE_SUFFIX: &[u8] = b"_VOTE";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn proposal_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, PROPOSAL_SUFFIX)
}

pub fn proposal_digest(view: View, height: Height, parent: &Digest, payload: &Digest) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + parent.len() + payload.len());
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(parent);
    msg.extend_from_slice(payload);
    msg.into()
}

pub fn vote_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, VOTE_SUFFIX)
}

pub fn vote_digest(view: View, height: Option<Height>, proposal: Option<&Digest>) -> Bytes {
    let mut msg = Vec::with_capacity(8 + proposal.map_or(0, |digest| 8 + digest.len()));
    msg.extend_from_slice(&view.to_be_bytes());
    if let Some(proposal) = proposal {
        msg.extend_from_slice(&height.unwrap().to_be_bytes());
        msg.extend_from_slice(proposal);
    }
    msg.into()
}

pub fn finalize_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

pub fn finalize_digest(view: View, height: Height, proposal: &Digest) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + proposal.len());
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(proposal);
    msg.into()
}
