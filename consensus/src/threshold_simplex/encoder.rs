use super::View;
use bytes::BufMut;
use commonware_codec::SizedInfo;
use commonware_utils::{union, Array};

pub const SEED_SUFFIX: &[u8] = b"_SEED";
pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn proposal_message<D: Array>(view: View, parent: View, payload: &D) -> Vec<u8> {
    let mut msg = Vec::with_capacity(u64::LEN_ENCODED + u64::LEN_ENCODED + D::LEN_ENCODED);
    msg.put_u64(view);
    msg.put_u64(parent);
    msg.extend_from_slice(payload);
    msg
}

pub fn nullify_message(nullify: View) -> Vec<u8> {
    nullify.to_be_bytes().to_vec()
}

pub fn seed_message(seed: View) -> Vec<u8> {
    seed.to_be_bytes().to_vec()
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
