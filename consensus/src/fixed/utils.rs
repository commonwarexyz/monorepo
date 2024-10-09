use crate::{Hash, Height, View};
use bytes::Bytes;
use sha2::{Digest, Sha256};

pub fn proposal_digest(view: View, height: Height, parent: &Hash, payload_hash: &Hash) -> Bytes {
    let mut msg = Vec::new();
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&parent);
    msg.extend_from_slice(&payload_hash);
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
    msg.extend_from_slice(&proposal_hash);
    msg.into()
}

// TODO: move to commonware-utils
pub fn hash(digest: &Bytes) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(digest);
    hasher.finalize().to_vec().into()
}
