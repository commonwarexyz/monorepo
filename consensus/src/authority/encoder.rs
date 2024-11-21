use super::wire;
use bytes::{BufMut, Bytes};
use commonware_cryptography::Digest;
use commonware_utils::union;

pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn proposal_message(index: &wire::Index, parent: &wire::Parent, payload: &Digest) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + 8 + parent.digest.len() + payload.len());
    msg.put_u64(index.view);
    msg.put_u64(index.height);
    msg.put_u64(parent.view);
    msg.extend_from_slice(&parent.digest);
    msg.extend_from_slice(payload);
    msg.into()
}

pub fn nullify_message(nullify: u64) -> Bytes {
    nullify.to_be_bytes().to_vec().into()
}

pub fn notarize_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

pub fn nullify_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

pub fn finalize_namespace(namespace: &Bytes) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}
