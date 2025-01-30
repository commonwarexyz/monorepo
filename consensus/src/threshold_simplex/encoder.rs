use super::View;
use bytes::{BufMut, Bytes};
use commonware_cryptography::Digest;
use commonware_utils::union;

pub const SEED_SUFFIX: &[u8] = b"_SEED";
pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn proposal_message<D: Digest>(view: View, parent: View, payload: &D) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + payload.len());
    msg.put_u64(view);
    msg.put_u64(parent);
    msg.extend_from_slice(payload);
    msg.into()
}

pub fn nullify_message(nullify: View) -> Bytes {
    nullify.to_be_bytes().to_vec().into()
}

pub fn seed_message(seed: View) -> Bytes {
    seed.to_be_bytes().to_vec().into()
}

pub fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

pub fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

pub fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

pub fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}
